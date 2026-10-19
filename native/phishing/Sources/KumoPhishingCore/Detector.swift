import Foundation
import CoreML

public final class PhishingDetector {
    private let model: MLModel
    private let tokenizer: MobileBERTTokenizer
    public let modelVersion: String
    public static let threshold = 0.9

    public init(resources: URL) throws {
        let infoURL = resources.appendingPathComponent("model-info.json")
        guard let infoSize = try infoURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, infoSize <= 65_536 else {
            throw PhishingError.invalidModel
        }
        let infoData = try Data(contentsOf: infoURL)
        guard let info = try JSONSerialization.jsonObject(with: infoData) as? [String: Any],
              info["schemaVersion"] as? Int == 1,
              let version = info["modelVersion"] as? String, version.count == 40,
              version.allSatisfy({ $0.isHexDigit }),
              info["windowSize"] as? Int == 128,
              info["stride"] as? Int == 64,
              info["maxWindows"] as? Int == 8,
              info["classIndex"] as? Int == 1,
              info["computeUnits"] as? String == "cpuOnly" else { throw PhishingError.invalidModel }
        self.modelVersion = version
        let vocabURL = resources.appendingPathComponent("vocab.txt")
        guard let vocabSize = try vocabURL.resourceValues(forKeys: [.fileSizeKey]).fileSize, vocabSize <= 2_000_000 else {
            throw PhishingError.invalidVocabulary
        }
        let vocabData = try Data(contentsOf: vocabURL, options: .mappedIfSafe)
        guard vocabData.count <= 2_000_000, let vocabulary = String(data: vocabData, encoding: .utf8) else {
            throw PhishingError.invalidVocabulary
        }
        self.tokenizer = try MobileBERTTokenizer(vocabularyText: vocabulary)
        let configuration = MLModelConfiguration()
        configuration.computeUnits = .cpuOnly
        self.model = try MLModel(contentsOf: resources.appendingPathComponent("PhishLang.mlmodelc"), configuration: configuration)
        guard Set(model.modelDescription.inputDescriptionsByName.keys) == ["input_ids", "attention_mask", "token_type_ids"],
              Set(model.modelDescription.outputDescriptionsByName.keys) == ["logits"] else { throw PhishingError.invalidModel }
        for name in ["input_ids", "attention_mask", "token_type_ids"] {
            guard let constraint = model.modelDescription.inputDescriptionsByName[name]?.multiArrayConstraint,
                  constraint.dataType == .int32, constraint.shape.map(\.intValue) == [1, 128] else {
                throw PhishingError.invalidModel
            }
        }
        guard let output = model.modelDescription.outputDescriptionsByName["logits"]?.multiArrayConstraint,
              output.shape.map(\.intValue) == [1, 2], output.dataType == .float32 else { throw PhishingError.invalidModel }
    }

    public func classify(_ text: String) throws -> [String: Any] {
        guard text.count <= HostProtocol.maximumTextCharacters else { throw PhishingError.invalidRequest }
        let started = ProcessInfo.processInfo.systemUptime
        let plan = WindowPlan(tokens: tokenizer.encode(text), tokenizer: tokenizer)
        var probability = 0.0
        for window in plan.windows {
            let result: Double = try autoreleasepool {
                let ids = try MLMultiArray(shape: [1, 128], dataType: .int32)
                let attention = try MLMultiArray(shape: [1, 128], dataType: .int32)
                let types = try MLMultiArray(shape: [1, 128], dataType: .int32)
                for index in 0..<128 {
                    ids[index] = NSNumber(value: window.ids[index])
                    attention[index] = NSNumber(value: window.attention[index])
                    types[index] = 0
                }
                let provider = try MLDictionaryFeatureProvider(dictionary: [
                    "input_ids": MLFeatureValue(multiArray: ids),
                    "attention_mask": MLFeatureValue(multiArray: attention),
                    "token_type_ids": MLFeatureValue(multiArray: types),
                ])
                let prediction = try model.prediction(from: provider)
                guard let logits = prediction.featureValue(for: "logits")?.multiArrayValue,
                      logits.count == 2 else { throw PhishingError.invalidModel }
                return try ModelMath.phishingProbability(logits: [logits[0].doubleValue, logits[1].doubleValue])
            }
            probability = max(probability, result)
        }
        return ["available": true, "modelVersion": modelVersion, "probability": probability,
                "threshold": Self.threshold, "verdict": probability >= Self.threshold ? "suspicious" : "no-signal",
                "tokenCount": plan.tokenCount, "windows": plan.windows.count,
                "truncated": plan.coverageLimited, "coverageLimited": plan.coverageLimited,
                "elapsedMs": (ProcessInfo.processInfo.systemUptime - started) * 1000]
    }
}

/// Owns at most one CPU-only model. Failure remains explicit and never becomes a benign verdict.
public final class PhishingService {
    private let detector: PhishingDetector?
    public init(resources: URL) {
        self.detector = try? PhishingDetector(resources: resources)
    }

    public func handle(_ data: Data) -> [String: Any] {
        var responseID: String?
        do {
            let request = try HostProtocol.Request(data: data)
            responseID = request.id
            guard let detector else {
                return ["id": request.id, "ok": request.type == "status", "available": false, "error": "model-unavailable"]
            }
            if request.type == "status" {
                return ["id": request.id, "ok": true, "available": true, "modelVersion": detector.modelVersion,
                        "computeUnits": "cpuOnly", "threshold": PhishingDetector.threshold]
            }
            guard let text = request.text else { throw PhishingError.invalidRequest }
            var result = try detector.classify(text)
            result["id"] = request.id
            result["ok"] = true
            return result
        } catch {
            var result: [String: Any] = ["ok": false, "available": detector != nil,
                                         "error": responseID == nil ? "invalid-request" : "inference-failed"]
            if let responseID { result["id"] = responseID }
            return result
        }
    }
}

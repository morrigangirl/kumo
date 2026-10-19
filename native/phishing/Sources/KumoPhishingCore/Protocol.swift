import Foundation

public enum HostProtocol {
    public static let allowedOrigin = "chrome-extension://eldkgppmnhligdekahicdcdndcoongio/"
    public static let standaloneOrigin = "chrome-extension://ejmohaggcahgfhmgkdiicnmmlpnhgfmi/"
    public static let maximumFrameBytes = 256 * 1024
    public static let maximumTextCharacters = 32_768

    /// The standalone caller is selected only by the helper's signed bundle metadata.
    /// Neither argv, the environment nor a Native Messaging request can choose a caller.
    public static func authorized(arguments: [String], bundleIdentifier: String? = nil, sealedOrigin: Any? = nil) -> Bool {
        let expected: String
        switch bundleIdentifier {
        case "app.kumo.phishlang":
            guard let value = sealedOrigin as? String, value == standaloneOrigin else { return false }
            expected = standaloneOrigin
        case nil, "app.kumo.phishing":
            guard sealedOrigin == nil else { return false }
            expected = allowedOrigin
        default:
            return false
        }
        return arguments.count == 2 && arguments[1] == expected
    }

    public static func readFrame(from handle: FileHandle) throws -> Data? {
        guard let header = try readExactly(4, from: handle, permitEOF: true) else { return nil }
        let length = header.enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << UInt32($1.offset * 8) }
        guard length > 0, length <= maximumFrameBytes else { throw PhishingError.oversizedFrame }
        guard let body = try readExactly(Int(length), from: handle, permitEOF: false) else {
            throw PhishingError.incompleteFrame
        }
        return body
    }

    private static func readExactly(_ count: Int, from handle: FileHandle, permitEOF: Bool) throws -> Data? {
        var result = Data()
        while result.count < count {
            guard let bytes = try handle.read(upToCount: count - result.count), !bytes.isEmpty else {
                if result.isEmpty && permitEOF { return nil }
                throw PhishingError.incompleteFrame
            }
            result.append(bytes)
        }
        return result
    }

    public static func framed(_ object: [String: Any]) throws -> Data {
        let body = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard body.count <= maximumFrameBytes else { throw PhishingError.oversizedFrame }
        let length = UInt32(body.count)
        var output = Data((0..<4).map { UInt8((length >> ($0 * 8)) & 0xFF) })
        output.append(body)
        return output
    }

    /// Diagnostic stdin remains bounded even when a writer splits its JSON across pipe writes.
    public static func readDiagnostic(from handle: FileHandle) throws -> Data {
        var result = Data()
        while let bytes = try handle.read(upToCount: min(8192, maximumFrameBytes + 1 - result.count)), !bytes.isEmpty {
            result.append(bytes)
            guard result.count <= maximumFrameBytes else { throw PhishingError.oversizedFrame }
        }
        return result
    }

    public struct Request {
        public let id: String
        public let type: String
        public let text: String?

        public init(data: Data) throws {
            guard data.count <= maximumFrameBytes,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let id = object["id"] as? String, !id.isEmpty, id.utf8.count <= 128,
                  let type = object["type"] as? String else { throw PhishingError.invalidRequest }
            let allowed: Set<String>
            switch type {
            case "status": allowed = ["id", "type"]
            case "classify": allowed = ["id", "type", "text"]
            default: throw PhishingError.invalidRequest
            }
            guard Set(object.keys) == allowed else { throw PhishingError.invalidRequest }
            if type == "classify" {
                guard let text = object["text"] as? String, text.count <= maximumTextCharacters else {
                    throw PhishingError.invalidRequest
                }
                self.text = text
            } else { self.text = nil }
            self.id = id
            self.type = type
        }
    }
}

public enum ModelMath {
    public static func phishingProbability(logits: [Double]) throws -> Double {
        guard logits.count == 2, logits.allSatisfy(\.isFinite) else { throw PhishingError.invalidModel }
        let maximum = max(logits[0], logits[1])
        let a = exp(logits[0] - maximum)
        let b = exp(logits[1] - maximum)
        return b / (a + b)
    }
}

import XCTest
import Foundation
@testable import KumoPhishingCore

final class PhishingTests: XCTestCase {
    private func tokenizer() throws -> MobileBERTTokenizer {
        try MobileBERTTokenizer(vocabularyText: "[PAD]\n[UNK]\n[CLS]\n[SEP]\nhello\nworld\n,\n!\ncafe\n中\n文\nplay\n##ing\n.\n")
    }

    private func request(_ object: [String: Any]) throws -> HostProtocol.Request {
        try HostProtocol.Request(data: JSONSerialization.data(withJSONObject: object))
    }

    func testCallerRequiresExactOriginAndNoExtraArguments() {
        XCTAssertTrue(HostProtocol.authorized(arguments: ["host", HostProtocol.allowedOrigin]))
        for origin in ["", "https://example.com/", HostProtocol.allowedOrigin + "evil", HostProtocol.allowedOrigin.uppercased(),
                       "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"] {
            XCTAssertFalse(HostProtocol.authorized(arguments: ["host", origin]))
        }
        XCTAssertFalse(HostProtocol.authorized(arguments: ["host"]))
        XCTAssertFalse(HostProtocol.authorized(arguments: ["host", HostProtocol.allowedOrigin, "--resources", "/tmp"]))
    }

    func testBasicTokensMatchUncasedBERTSemantics() throws {
        let value = "HéLLo,\tWORLD! CAFÉ\u{2003}中文\u{0000}\u{FFFD} playing."
        XCTAssertEqual(MobileBERTTokenizer.basicTokens(value), ["hello", ",", "world", "!", "cafe", "中", "文", "playing", "."])
        XCTAssertEqual(try tokenizer().encode(value), [4, 6, 5, 7, 8, 9, 10, 11, 12, 13])
        XCTAssertEqual(MobileBERTTokenizer.basicTokens("a\u{000B}b\u{000C}c\u{E000}d\u{0378}e"), ["abcde"])
    }

    func testWordPieceFailureDoesNotKeepPartialToken() throws {
        let tokenizer = try tokenizer()
        XCTAssertEqual(tokenizer.encode("playing playz"), [11, 12, 1])
        XCTAssertEqual(tokenizer.encode(String(repeating: "a", count: 101)), [1])
        XCTAssertEqual(tokenizer.encode("unknown"), [1])
    }

    func testAddedSpecialTokensRemainCaseSensitiveAndSplitEmbeddedText() throws {
        let tokenizer = try tokenizer()
        XCTAssertEqual(tokenizer.encode("hello[CLS]world [UNK][PAD][SEP]"), [4, 2, 5, 1, 0, 3])
        XCTAssertEqual(tokenizer.encode("[cls]"), [1, 1, 1])
        XCTAssertEqual(tokenizer.encode("[CLS]\u{20DD}hello"), [2, 1])
        let started = ProcessInfo.processInfo.systemUptime
        XCTAssertEqual(tokenizer.encode(String(repeating: "[PAD]", count: 6553)), Array(repeating: 0, count: 6553))
        // A generous ceiling catches the previous 14-second quadratic scan while
        // allowing a slow CI runner to exercise the maximum permitted input.
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - started, 2)
    }

    func testOfficialTokenizerReferenceWhenSupplied() throws {
        guard let directory = ProcessInfo.processInfo.environment["KUMO_PHISHING_REFERENCE_DIRECTORY"] else {
            throw XCTSkip("Supply the pinned offline reference directory for upstream tokenizer parity.")
        }
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        let tokenizer = try MobileBERTTokenizer(vocabularyText: String(contentsOf: root.appendingPathComponent("vocab.txt"), encoding: .utf8))
        let data = try Data(contentsOf: root.appendingPathComponent("tokenizer-reference.json"))
        let reference = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cases = try XCTUnwrap(reference["cases"] as? [[String: Any]])
        XCTAssertFalse(cases.isEmpty)
        XCTAssertEqual(tokenizer.padID, 0)
        XCTAssertEqual(tokenizer.unknownID, 100)
        XCTAssertEqual(tokenizer.clsID, 101)
        XCTAssertEqual(tokenizer.sepID, 102)
        for value in cases {
            let name = try XCTUnwrap(value["name"] as? String)
            let text = try XCTUnwrap(value["text"] as? String)
            let expected = try XCTUnwrap(value["ids"] as? [Int])
            let ids = tokenizer.encode(text)
            XCTAssertEqual(ids.map(Int.init), expected, name)
            let first = try XCTUnwrap(WindowPlan(tokens: ids, tokenizer: tokenizer).windows.first)
            XCTAssertEqual(first.ids.map(Int.init), try XCTUnwrap(value["input_ids"] as? [Int]), name)
            XCTAssertEqual(first.attention.map(Int.init), try XCTUnwrap(value["attention_mask"] as? [Int]), name)
        }
    }

    func testVocabularyRejectsMissingAndDuplicateSpecialTokens() {
        XCTAssertThrowsError(try MobileBERTTokenizer(vocabularyText: "hello\n"))
        XCTAssertThrowsError(try MobileBERTTokenizer(vocabularyText: "[PAD]\n[UNK]\n[CLS]\n[SEP]\nhello\nhello\n"))
        XCTAssertThrowsError(try MobileBERTTokenizer(vocabularyText: "[PAD]\n[UNK]\n[CLS]\n[SEP]\n\n"))
    }

    func testShortAndEmptyTextAlwaysHaveOnePaddedWindow() throws {
        let tokenizer = try tokenizer()
        let empty = WindowPlan(tokens: [], tokenizer: tokenizer)
        XCTAssertEqual(empty.windows.count, 1)
        XCTAssertEqual(empty.windows[0].ids.count, 128)
        XCTAssertEqual(Array(empty.windows[0].ids.prefix(4)), [2, 3, 0, 0])
        XCTAssertEqual(empty.windows[0].attention.reduce(0, +), 2)
        XCTAssertFalse(empty.coverageLimited)
        let short = WindowPlan(tokens: [4, 5], tokenizer: tokenizer)
        XCTAssertEqual(Array(short.windows[0].ids.prefix(5)), [2, 4, 5, 3, 0])
        XCTAssertEqual(short.windows[0].attention.reduce(0, +), 4)
    }

    func testWindowBoundsAndTailCoverage() throws {
        let tokenizer = try tokenizer()
        let exact = WindowPlan(tokens: Array(repeating: 4, count: 126), tokenizer: tokenizer)
        XCTAssertEqual(exact.windows.count, 1)
        let extra = WindowPlan(tokens: Array(repeating: 4, count: 127), tokenizer: tokenizer)
        XCTAssertEqual(extra.windows.map(\.offset), [0, 64])
        let limit = WindowPlan(tokens: Array(repeating: 4, count: 574), tokenizer: tokenizer)
        XCTAssertEqual(limit.windows.count, 8)
        XCTAssertFalse(limit.coverageLimited)
        let large = WindowPlan(tokens: (0..<32_768).map { Int32($0) }, tokenizer: tokenizer)
        XCTAssertEqual(large.windows.map(\.offset), [0, 64, 128, 192, 256, 320, 384, 32_642])
        XCTAssertTrue(large.coverageLimited)
        XCTAssertEqual(large.tokenCount, 32_768)
        XCTAssertEqual(large.windows.last?.ids[126], 32_767)
        XCTAssertEqual(large.windows.last?.ids[127], tokenizer.sepID)
        XCTAssertTrue(large.windows.allSatisfy { $0.ids.count == 128 && $0.attention.count == 128 })
    }

    func testStableSoftmaxRejectsMalformedLogits() throws {
        XCTAssertEqual(try ModelMath.phishingProbability(logits: [0, 0]), 0.5, accuracy: 1e-12)
        XCTAssertEqual(try ModelMath.phishingProbability(logits: [1000, 1001]), 0.7310585786300049, accuracy: 1e-12)
        XCTAssertEqual(try ModelMath.phishingProbability(logits: [1000, -1000]), 0)
        for values: [Double] in [[], [1], [1, 2, 3], [.nan, 0], [0, .infinity], [-.infinity, 0]] {
            XCTAssertThrowsError(try ModelMath.phishingProbability(logits: values))
        }
    }

    func testRequestSchemaAndBounds() throws {
        XCTAssertEqual(try request(["id": "a", "type": "status"]).type, "status")
        XCTAssertEqual(try request(["id": "b", "type": "classify", "text": ""]).text, "")
        XCTAssertNoThrow(try request(["id": "b", "type": "classify", "text": String(repeating: "x", count: 32_768)]))
        let invalid: [[String: Any]] = [
            ["id": "", "type": "status"], ["id": 1, "type": "status"],
            ["id": String(repeating: "x", count: 129), "type": "status"],
            ["id": "x", "type": "unknown"], ["id": "x", "type": "status", "text": "hi"],
            ["id": "x", "type": "classify"], ["id": "x", "type": "classify", "text": 4],
            ["id": "x", "type": "classify", "text": "hi", "url": "https://example.com"],
            ["id": "x", "type": "classify", "text": String(repeating: "x", count: 32_769)],
        ]
        for object in invalid { XCTAssertThrowsError(try request(object)) }
        for text in ["null", "[]", "false", "{", "\"hi\""] {
            XCTAssertThrowsError(try HostProtocol.Request(data: Data(text.utf8)))
        }
        XCTAssertThrowsError(try HostProtocol.Request(data: Data(repeating: 32, count: HostProtocol.maximumFrameBytes + 1)))
    }

    private func readFrame(_ bytes: Data) throws -> Data? {
        let pipe = Pipe()
        // Test fixtures fit in a pipe without a writer thread.
        try pipe.fileHandleForWriting.write(contentsOf: bytes)
        try pipe.fileHandleForWriting.close()
        return try HostProtocol.readFrame(from: pipe.fileHandleForReading)
    }

    func testFramingRoundTripAndCleanEOF() throws {
        let frame = try HostProtocol.framed(["id": "测试", "ok": true])
        let payload = try XCTUnwrap(readFrame(frame))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: payload) as? [String: Any])
        XCTAssertEqual(object["id"] as? String, "测试")
        XCTAssertEqual(object["ok"] as? Bool, true)
        XCTAssertNil(try readFrame(Data()))
        XCTAssertEqual(Int(frame[0]) + Int(frame[1]) * 256, payload.count)
    }

    func testFramingRejectsTruncationAndOversizeBeforeReadingBody() throws {
        for bytes: [UInt8] in [[1], [1, 0, 0], [5, 0, 0, 0, 123], [0, 0, 0, 0], [1, 0, 4, 0], [255, 255, 255, 255]] {
            XCTAssertThrowsError(try readFrame(Data(bytes)))
        }
        XCTAssertThrowsError(try HostProtocol.framed(["text": String(repeating: "x", count: HostProtocol.maximumFrameBytes)]))
    }

    func testMissingAndCorruptModelAreExplicitlyUnavailable() throws {
        let resources = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: resources) }
        for mode in 0..<3 {
            if mode == 1 { try Data("{}".utf8).write(to: resources.appendingPathComponent("model-info.json")) }
            if mode == 2 {
                let info: [String: Any] = ["schemaVersion": 1, "modelVersion": String(repeating: "a", count: 40),
                                          "windowSize": 128, "stride": 64, "maxWindows": 8, "classIndex": 1,
                                          "computeUnits": "cpuOnly"]
                try JSONSerialization.data(withJSONObject: info).write(to: resources.appendingPathComponent("model-info.json"))
                try Data("[PAD]\n[UNK]\n[CLS]\n[SEP]\n".utf8).write(to: resources.appendingPathComponent("vocab.txt"))
                let model = resources.appendingPathComponent("PhishLang.mlmodelc", isDirectory: true)
                try FileManager.default.createDirectory(at: model, withIntermediateDirectories: true)
                try Data("invalid compiled model".utf8).write(to: model.appendingPathComponent("model.mil"))
            }
            let service = PhishingService(resources: resources)
            let status = service.handle(try JSONSerialization.data(withJSONObject: ["id": "status", "type": "status"]))
            XCTAssertEqual(status["ok"] as? Bool, true)
            XCTAssertEqual(status["available"] as? Bool, false)
            XCTAssertEqual(status["error"] as? String, "model-unavailable")
            let result = service.handle(try JSONSerialization.data(withJSONObject: ["id": "classify", "type": "classify", "text": "synthetic"]))
            XCTAssertEqual(result["ok"] as? Bool, false)
            XCTAssertEqual(result["available"] as? Bool, false)
            XCTAssertNil(result["verdict"])
        }
    }
}

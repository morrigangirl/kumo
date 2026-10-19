import Foundation

public enum PhishingError: Error {
    case invalidRequest, oversizedFrame, incompleteFrame, unavailable, invalidModel, invalidVocabulary
}

/// BERT's uncased BasicTokenizer followed by greedy WordPiece. No page values are logged.
public struct MobileBERTTokenizer {
    private let vocabulary: [String: Int32]
    public let unknownID: Int32
    public let clsID: Int32
    public let sepID: Int32
    public let padID: Int32

    public init(vocabularyText: String) throws {
        var lines = vocabularyText.components(separatedBy: "\n")
        if lines.last == "" { lines.removeLast() }
        guard !lines.isEmpty, lines.count <= 100_000 else { throw PhishingError.invalidVocabulary }
        var vocabulary: [String: Int32] = [:]
        for (index, line) in lines.enumerated() {
            guard !line.isEmpty, vocabulary[line] == nil else { throw PhishingError.invalidVocabulary }
            vocabulary[line] = Int32(index)
        }
        guard let unknown = vocabulary["[UNK]"], let cls = vocabulary["[CLS]"],
              let sep = vocabulary["[SEP]"], let pad = vocabulary["[PAD]"] else {
            throw PhishingError.invalidVocabulary
        }
        self.vocabulary = vocabulary
        self.unknownID = unknown
        self.clsID = cls
        self.sepID = sep
        self.padID = pad
    }

    public static func isWhitespace(_ scalar: Unicode.Scalar) -> Bool {
        [9, 10, 13, 32].contains(scalar.value) || scalar.properties.generalCategory == .spaceSeparator
    }

    private static func isChinese(_ value: UInt32) -> Bool {
        (0x4E00...0x9FFF).contains(value) || (0x3400...0x4DBF).contains(value) ||
        (0x20000...0x2A6DF).contains(value) || (0x2A700...0x2B73F).contains(value) ||
        (0x2B740...0x2B81F).contains(value) || (0x2B820...0x2CEAF).contains(value) ||
        (0xF900...0xFAFF).contains(value) || (0x2F800...0x2FA1F).contains(value)
    }

    private static func isPunctuation(_ scalar: Unicode.Scalar) -> Bool {
        let value = scalar.value
        if (33...47).contains(value) || (58...64).contains(value) ||
            (91...96).contains(value) || (123...126).contains(value) { return true }
        switch scalar.properties.generalCategory {
        case .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation,
             .initialPunctuation, .finalPunctuation, .otherPunctuation: return true
        default: return false
        }
    }

    public static func basicTokens(_ text: String) -> [String] {
        var cleaned = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            if scalar.value == 0 || scalar.value == 0xFFFD { continue }
            if isWhitespace(scalar) { cleaned.append(" "); continue }
            switch scalar.properties.generalCategory {
            case .control, .format, .privateUse, .unassigned, .surrogate: continue
            default: break
            }
            if isChinese(scalar.value) { cleaned.append(" "); cleaned.append(scalar); cleaned.append(" ") }
            else { cleaned.append(scalar) }
        }
        var result: [String] = []
        for token in String(cleaned).split(whereSeparator: { $0 == " " }) {
            let lower = String(token).lowercased().decomposedStringWithCanonicalMapping
            var current = String.UnicodeScalarView()
            for scalar in lower.unicodeScalars {
                if scalar.properties.generalCategory == .nonspacingMark { continue }
                if isPunctuation(scalar) {
                    if !current.isEmpty { result.append(String(current)); current = .init() }
                    result.append(String(scalar))
                } else { current.append(scalar) }
            }
            if !current.isEmpty { result.append(String(current)) }
        }
        return result
    }

    public func encode(_ text: String) -> [Int32] {
        var output: [Int32] = []
        // Transformers' added-token pass preserves these case-sensitive BERT specials
        // before BasicTokenizer, including when embedded inside another word.
        let specials = ["[UNK]", "[CLS]", "[SEP]", "[PAD]", "[MASK]"].compactMap { token -> ([Unicode.Scalar], Int32)? in
            guard let id = vocabulary[token] else { return nil }
            return (Array(token.unicodeScalars), id)
        }
        let scalars = Array(text.unicodeScalars)
        var start = 0
        var cursor = 0
        // Scan once. Repeated substring searches become quadratic for pages that
        // contain thousands of BERT special-token strings.
        while cursor < scalars.count {
            if scalars[cursor].value == 91,
               let special = specials.first(where: {
                   cursor + $0.0.count <= scalars.count &&
                   scalars[cursor..<(cursor + $0.0.count)].elementsEqual($0.0)
               }) {
                if start < cursor {
                    output.append(contentsOf: wordPieces(String(String.UnicodeScalarView(scalars[start..<cursor]))))
                }
                output.append(special.1)
                cursor += special.0.count
                start = cursor
            } else { cursor += 1 }
        }
        if start < scalars.count {
            output.append(contentsOf: wordPieces(String(String.UnicodeScalarView(scalars[start...]))))
        }
        return output
    }

    private func wordPieces(_ text: String) -> [Int32] {
        var output: [Int32] = []
        for token in Self.basicTokens(text) {
            let characters = token.unicodeScalars.map(String.init)
            if characters.count > 100 { output.append(unknownID); continue }
            var start = 0
            var pieces: [Int32] = []
            var failed = false
            while start < characters.count {
                var end = characters.count
                var found: Int32?
                while end > start {
                    let piece = (start == 0 ? "" : "##") + characters[start..<end].joined()
                    if let id = vocabulary[piece] { found = id; break }
                    end -= 1
                }
                guard let found else { failed = true; break }
                pieces.append(found)
                start = end
            }
            output.append(contentsOf: failed ? [unknownID] : pieces)
        }
        return output
    }
}

public struct TokenWindow: Equatable {
    public let ids: [Int32]
    public let attention: [Int32]
    public let offset: Int
}

public struct WindowPlan {
    public let windows: [TokenWindow]
    public let tokenCount: Int
    public let coverageLimited: Bool

    public init(tokens: [Int32], tokenizer: MobileBERTTokenizer) {
        let payload = 126
        var offsets = [0]
        while let previous = offsets.last, previous + payload < tokens.count, offsets.count <= 8 {
            offsets.append(previous + 64)
        }
        let limited = offsets.count > 8
        if limited { offsets = Array(offsets.prefix(7)) + [max(0, tokens.count - payload)] }
        self.windows = offsets.map { offset in
            let end = min(tokens.count, offset + payload)
            let body = offset < end ? Array(tokens[offset..<end]) : []
            var ids = [tokenizer.clsID] + body + [tokenizer.sepID]
            let activeCount = ids.count
            ids += Array(repeating: tokenizer.padID, count: 128 - activeCount)
            return TokenWindow(ids: ids, attention: Array(repeating: 1, count: activeCount) +
                               Array(repeating: 0, count: 128 - activeCount), offset: offset)
        }
        self.tokenCount = tokens.count
        self.coverageLimited = limited
    }
}

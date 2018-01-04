//
//  RandomData.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/10/07.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation
import Darwin

struct CypherCharacterSet: OptionSet, Hashable {
    let rawValue: UInt32
    init(rawValue: UInt32) { self.rawValue = rawValue }
    var hashValue: Int { return Int(self.rawValue) }
    
    static var iterator: AnyIterator<CypherCharacterSet> {
        var value: CypherCharacterSet.RawValue = 1
        return AnyIterator {
            guard value != CypherCharacterSet.TypeEnd.rawValue else {
                return nil
            }
            let r = CypherCharacterSet(rawValue: value)
            value <<= 1
            return r
        }
    }
    
    func makeIterator() -> AnyIterator<CypherCharacterSet> {
        var bit: UInt32 = 1
        return AnyIterator {
            while bit < CypherCharacterSet.TypeEnd.rawValue &&
                !self.contains(CypherCharacterSet(rawValue: bit)) {
                bit <<= 1
            }
            guard bit < CypherCharacterSet.TypeEnd.rawValue else {
                return nil
            }
            let r = CypherCharacterSet(rawValue: bit)
            bit <<= 1
            return r
        }
    }
    
    var count: Int {
        return self.makeIterator().map {_ in 1}.reduce(0) {$0+$1}
    }
    
    static let ExclamationMark         = CypherCharacterSet(rawValue: 0x00000001) // "!"
    static let QuotationMark           = CypherCharacterSet(rawValue: 0x00000002) // '"'
    static let NumberSign              = CypherCharacterSet(rawValue: 0x00000004) // "#"
    static let DollarSign              = CypherCharacterSet(rawValue: 0x00000008) // "$"
    static let PercentSign             = CypherCharacterSet(rawValue: 0x00000010) // "%"
    static let Ampersand               = CypherCharacterSet(rawValue: 0x00000020) // "&"
    static let Apostrophe              = CypherCharacterSet(rawValue: 0x00000040) // "'"
    static let Parenthesises           = CypherCharacterSet(rawValue: 0x00000080) // "(", ")"
    static let Asterisk                = CypherCharacterSet(rawValue: 0x00000100) // "*"
    static let PlusSign                = CypherCharacterSet(rawValue: 0x00000200) // "+"
    static let Comma                   = CypherCharacterSet(rawValue: 0x00000400) // ","
    static let HyphenMinus             = CypherCharacterSet(rawValue: 0x00000800) // "-"
    static let FullStop                = CypherCharacterSet(rawValue: 0x00001000) // "."
    static let Solidus                 = CypherCharacterSet(rawValue: 0x00002000) // "/"
    static let DecimalDigits           = CypherCharacterSet(rawValue: 0x00004000) // "0".."9"
    static let Colon                   = CypherCharacterSet(rawValue: 0x00008000) // ":"
    static let Semicolon               = CypherCharacterSet(rawValue: 0x00010000) // ";"
    static let LessAndGreaterThanSigns = CypherCharacterSet(rawValue: 0x00020000) // "<", ">"
    static let EqualsSign              = CypherCharacterSet(rawValue: 0x00040000) // "="
    static let QuestionMark            = CypherCharacterSet(rawValue: 0x00080000) // "?"
    static let CommercialAt            = CypherCharacterSet(rawValue: 0x00100000) // "@"
    static let UppercaseLatinAlphabets = CypherCharacterSet(rawValue: 0x00200000) // "A".."Z"
    static let SquareBrackets          = CypherCharacterSet(rawValue: 0x00400000) // "[", "]"
    static let ReverseSolidus          = CypherCharacterSet(rawValue: 0x00800000) // "\"
    static let CircumflexAccent        = CypherCharacterSet(rawValue: 0x01000000) // "^"
    static let LowLine                 = CypherCharacterSet(rawValue: 0x02000000) // "_"
    static let GraveAccent             = CypherCharacterSet(rawValue: 0x04000000) // "`"
    static let LowercaseLatinAlphabets = CypherCharacterSet(rawValue: 0x08000000) // "a".."z"
    static let CurlyBrackets           = CypherCharacterSet(rawValue: 0x10000000) // "{", "}"
    static let VerticalLine            = CypherCharacterSet(rawValue: 0x20000000) // "|"
    static let Tilde                   = CypherCharacterSet(rawValue: 0x40000000) // "~"
    static let TypeEnd                 = CypherCharacterSet(rawValue: 0x80000000) // Type End
    
    static let UpperCaseLettersSet:     CypherCharacterSet = [.DecimalDigits, .UppercaseLatinAlphabets]
    static let LowerCaseLettersSet:     CypherCharacterSet = [.DecimalDigits, .LowercaseLatinAlphabets]
    static let AlphaNumericsSet:        CypherCharacterSet = [.DecimalDigits, .UppercaseLatinAlphabets, .LowercaseLatinAlphabets] // 0..9 A-Za-z
    static let Base64Set:               CypherCharacterSet = [.AlphaNumericsSet, .PlusSign, .Solidus] // 0..9 A-Za-z + /
    static let ArithmeticCharactersSet: CypherCharacterSet = [.AlphaNumericsSet, .PlusSign, .HyphenMinus, .Asterisk, .Solidus]
    static let AlphaNumericSymbolsSet:  CypherCharacterSet = [
        .AlphaNumericsSet,
        .ExclamationMark,
        .NumberSign,
        .DollarSign,
        .PercentSign,
        .Ampersand,
        .Asterisk,
        .PlusSign,
        .HyphenMinus,
        .Solidus,
        .DecimalDigits,
        .EqualsSign,
        .QuestionMark,
        .CommercialAt,
        .CircumflexAccent,
        .LowLine,
        .VerticalLine,
        .Tilde
    ]
    static let AllCharactersSet = CypherCharacterSet(rawValue: CypherCharacterSet.TypeEnd.rawValue - 1)

    fileprivate var tostr: String {
        let s: String
        switch self {
        case .ExclamationMark:         s = "!"
        case .QuotationMark:           s = "\""
        case .NumberSign:              s = "#"
        case .DollarSign:              s = "$"
        case .PercentSign:             s = "%"
        case .Ampersand:               s = "&"
        case .Apostrophe:              s = "'"
        case .Parenthesises:           s = "()"
        case .Asterisk:                s = "*"
        case .PlusSign:                s = "+"
        case .Comma:                   s = ""
        case .HyphenMinus:             s = "-"
        case .FullStop:                s = "."
        case .Solidus:                 s = "/"
        case .DecimalDigits:           s = "0123456789"
        case .Colon:                   s = ":"
        case .Semicolon:               s = ";"
        case .LessAndGreaterThanSigns: s = "<>"
        case .EqualsSign:              s = "="
        case .QuestionMark:            s = "?"
        case .CommercialAt:            s = "@"
        case .UppercaseLatinAlphabets: s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        case .SquareBrackets:          s = "[]"
        case .ReverseSolidus:          s = "\\"
        case .CircumflexAccent:        s = "^"
        case .LowLine:                 s = "_"
        case .GraveAccent:             s = "`"
        case .LowercaseLatinAlphabets: s = "abcdefghijklmnopqrstuvwxyz"
        case .CurlyBrackets:           s = "{}"
        case .VerticalLine:            s = "|"
        case .Tilde:                   s = "~"
        default:                       s = "UNKNOWN rawValue=\(self.rawValue) "
        }
        return s
    }

    var string: String {
        return CypherCharacterSet.iterator.flatMap {
            self.contains($0) ? $0.tostr : nil
        }.joined()
    }
    
    var description: String {
        let specialSets = [
            CypherCharacterSet.UpperCaseLettersSet: "0-9A-Z",
            CypherCharacterSet.LowerCaseLettersSet: "0-9a-z",
            CypherCharacterSet.AlphaNumericsSet: "0-9A-Za-z",
            CypherCharacterSet.Base64Set: "0-9A-Za-z +/",
            CypherCharacterSet.ArithmeticCharactersSet: "0-9A-Za-z +-*/",
            CypherCharacterSet.AlphaNumericSymbolsSet: "0-9A-Za-z +-*/= !#$%&?@^_|~"
            ].sorted(by: {$0.key.count > $1.key.count})
        
        var val = self
        var strArray: [String] = []
        specialSets.forEach { e in
            if val.contains(e.key) {
                strArray.append(e.value)
                val.remove(e.key)
            }
        }
        strArray.append(val.string)

        return strArray.joined(separator: " ")
    }
}

enum J1RandomDataError: Error {
    case unexpected
    case outOfRange
    case secError(error: OSStatus)
}

class J1RandomData {
    static let shared = J1RandomData()
    static let MaxCount = 1024
    
    func get(count: Int) throws -> Data {
        guard case 1...J1RandomData.MaxCount = count else {
            throw J1RandomDataError.outOfRange
        }
        
        // http://blog.sarabande.jp/post/92199466318
        // allocate zeroed memory area whose size is length
        var data = Data(count: count)
        
        // generate a random data and write to the buffer
        var error: OSStatus = errSecSuccess
        data.withUnsafeMutableBytes { bytes in
            error = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
        }
        guard error == errSecSuccess else {
            throw J1RandomDataError.secError(error: error)
        }
        return data
    }
    
    func get(count: Int, in charSet: CypherCharacterSet ) throws -> String {
        guard case 1...J1RandomData.MaxCount = count else {
            throw J1RandomDataError.outOfRange
        }
        
        var charArray: [Character] = charSet.string.map { $0 }
        let charCount = charArray.count
        let indexTotalCount: Int = {
            var b = 1
            var n = 0 // n bits are needed to represent charCount
            while b < charCount {
                b <<= 1
                n +=  1
            }
            return (n * count + 7) / 8  // how many bytes are needed to represent charArray
        }()
        
        var string = ""
        string.reserveCapacity(count)
        while string.count < count {
            let indexCount = min(indexTotalCount, J1RandomData.MaxCount)
            // J1RandomData.get generates count bytes random data
            // calculate the enough size of random data

            let rand = try self.get(count: indexCount)
            // let rand = Data(count: indexCount) // when DEBUG
            let indecies = rand.als(radix: UInt8(charCount))

            let str = String( indecies.map { charArray[Int($0)] } )
            guard str.count > 0 else {
                assertionFailure()
                throw J1RandomDataError.unexpected
            }
            string  += str
        }
        if string.count > count {
            string.removeLast(string.count - count) // adjust length
        }
        return string
    }
}



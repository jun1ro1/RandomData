//
//  main.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/10/07.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

print("Hello, World!")

for c in CypherCharacterSet.iterator {
    print(String(format:"%08x", c.rawValue), ":", c.string)
}
print()

for n in [8, 10, 16, 32, 64, 256, 1024 ] {
    print("length =", n)
    for s: CypherCharacterSet in
        [.DecimalDigits, .UpperCaseLettersSet, .LowerCaseLettersSet, .AlphaNumericsSet,
         .Base64Set, .ArithmeticCharactersSet, .AlphaNumericSymbolsSet, .AllCharactersSet  ] {
            var counts: [Character: Int] = Dictionary(uniqueKeysWithValues: s.string.map { ($0, 0) })
            guard let str = J1RandomData.shared.get(count: n, in: s) else {
                print("ERROR")
                continue
            }
            print("characters=", s.description, "count=", str.count)
            print(str)
            str.forEach { counts[$0]! += 1 }
            print()
            var count = 1
            counts.keys.sorted().forEach {
                print($0, ":", String(format:"%3d", counts[$0] ?? -1),
                      separator: "", terminator: (count % 16 == 0 ? "\n" : " "))
                count += 1
            }
            print(); print()
    }
}

print("==========")

let password = "The quick brown fox jumps over the lazy white dog."
J1CryptorCore.shared.create(password: password)

let cryptor = J1Cryptor()
print("----------")
cryptor.open(password: password)
let plain       = "The plain text. very long long 123456789012345678901234567890"
let plainData   = plain.data(using: .utf8, allowLossyConversion: true)!
let cipher      = cryptor.encrypt(plain: plainData)!
let replainData = cryptor.decrypt(cipher: cipher)!
let replain     = String(data: replainData, encoding: .utf8)!
cryptor.close()

print("plain       =", plain)
print("plainData   =", plainData   as NSData)
print("cipher      =", cipher      as NSData)
print("replainData =", replainData as NSData)
print("replain     =", replain)


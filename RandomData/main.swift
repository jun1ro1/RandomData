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
    print("----------")
    
    let cryptor = J1CryptorCore()
    
    let password = "The quick brown fox jumps over the lazy white dog."
    cryptor.create(password: password)
    print("----------")
    cryptor.open(password: password)
    
    
    
//    let cipher = Cipher()
//    cipher.prepare(passPhrase: "The quick brown fox jumps over the lazy white dog.")
//    print("----------")
//    cipher.restore(passPhrase: "The quick brown fox jumps over the lazy white dog.")
//
//    print("----------")
//    let data = J1RandomData.shared.get(count: 16)
//    print("plain data=", data! as NSData)
//    print("---")
//
//    let enc = cipher.withCEK(passPhrase: "The quick brown fox jumps over the lazy white dog.") {
//        cek in cipher.encrypt(CEK:cek, data!)!
//    }
//    print("enc   data=", enc! as NSData)
//    print("---")
//
//    let dec = cipher.withCEK(passPhrase: "The quick brown fox jumps over the lazy white dog.") {
//        cek in cipher.decrypt(CEK:cek, enc!)!
//    }
//    print("dec   data=", dec! as NSData)
//    print("---")
//
}



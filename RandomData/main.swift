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
         .Base64Set, .ArithmeticCharactersSet, .AlphaNumericSymbolsSet, .AllCharactersSet ] {
            var counts: [Character: Int] = Dictionary(uniqueKeysWithValues: s.string.map { ($0, 0) })
            guard let str = J1RandomData.shared.get(count: n, in: s) else {
                print("ERROR")
                continue
            }
            print("characters=", s.description, "count=", str.count)
            print(str)
            str.characters.forEach { counts[$0]! += 1 }
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
}



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
var plain       = "The plain text. very long long 123456789012345678901234567890"
var plainData   = plain.data(using: .utf8, allowLossyConversion: true)!
var cipher      = cryptor.encrypt(plain: plainData)!
var replainData = cryptor.decrypt(cipher: cipher)!
var replain     = String(data: replainData, encoding: .utf8)!
cryptor.close()

print("plain       =", plain)
print("plainData   =", plainData   as NSData)
print("cipher      =", cipher      as NSData)
print("replainData =", replainData as NSData)
print("replain     =", replain)

cryptor.open(password: password) {
    plain       = """
    An die Freude

    O Freunde, nicht diese Töne!
    Sondern laßt uns angenehmere
    anstimmen und freudenvollere.

    Freude, schöner Götterfunken,
    Tochter aus Elysium
    Wir betreten feuertrunken.
    Himmlische, dein Heiligtum!

    Deine Zauber binden wieder,
    Was die Mode streng geteilt;
    Alle Menschen werden Brüder,
    Wo dein sanfter Flügel weilt.

    Wem der große Wurf gelungen,
    Eines Freundes Freund zu sein,
    Wer ein holdes Weib errungen,
    Mische seinen Jubel ein!

    Ja, wer auch nur eine Seele
    Sein nennt auf dem Erdenrund!
    Und wer's nie gekonnt, der stehle
    Weinend sich aus diesem Bund!

    Freude trinken alle Wesen
    An den Brüsten der Natur;
    Alle Guten, alle Bösen
    Folgen ihrer Rosenspur.

    Küsse gab sie uns und Reben,
    Einen Freund, geprüft im Tod;
    Wollust ward dem Wurm gegeben,
    und der Cherub steht vor Gott.

    Froh, wie seine Sonnen fliegen
    Durch des Himmels prächt'gen Plan,
    Laufet, Brüder, eure Bahn,
    Freudig, wie ein Held zum Siegen.

    Seid umschlungen, Millionen!
    Diesen Kuss der ganzen Welt!
    Brüder, über'm Sternenzelt
    Muß ein lieber Vater wohnen.

    Ihr stürzt nieder, Millionen?
    Ahnest du den Schöpfer, Welt?
    Such' ihn über'm Sternenzelt!
    Über Sternen muß er wohnen.
"""
    plainData   = plain.data(using: .utf8, allowLossyConversion: true)!
    cipher      = cryptor.encrypt(plain: plainData)!
    replainData = cryptor.decrypt(cipher: cipher)!
    replain     = String(data: replainData, encoding: .utf8)!

    print("plain       =", plain)
    print("plainData   =", plainData   as NSData)
    print("cipher      =", cipher      as NSData)
    print("replainData =", replainData as NSData)
    print("replain     =", replain)
}


cryptor.open(password: password) {
    plain       = """
    「歓喜に寄せて」

    おお友よ、このような音ではない！
    我々はもっと心地よい
    もっと歓喜に満ち溢れる歌を歌おうではないか
    （ベートーヴェン作詞）

    歓喜よ、神々の麗しき霊感よ
    天上の楽園の乙女よ
    我々は火のように酔いしれて
    崇高な汝（歓喜）の聖所に入る

    汝が魔力は再び結び合わせる
    （1803年改稿）
    時流が強く切り離したものを
    すべての人々は兄弟となる
    （1785年初稿:
    時流の刀が切り離したものを
    貧しき者らは王侯の兄弟となる）
    汝の柔らかな翼が留まる所で

    ひとりの友の友となるという
    大きな成功を勝ち取った者
    心優しき妻を得た者は
    彼の歓声に声を合わせよ

    そうだ、地上にただ一人だけでも
    心を分かち合う魂があると言える者も歓呼せよ
    そしてそれがどうしてもできなかった者は
    この輪から泣く泣く立ち去るがよい

    すべての被造物は
    創造主の乳房から歓喜を飲み、
    すべての善人とすべての悪人は
    創造主の薔薇の踏み跡をたどる。

    口づけと葡萄酒と死の試練を受けた友を
    創造主は我々に与えた
    快楽は虫けらのような弱い人間にも与えられ
    智天使ケルビムは神の御前に立つ

    天の星々がきらびやかな天空を
    飛びゆくように、楽しげに
    兄弟たちよ、自らの道を進め
    英雄のように喜ばしく勝利を目指せ

    抱擁を受けよ、諸人（もろびと）よ！
    この口づけを全世界に！
    兄弟よ、この星空の上に
    ひとりの父なる神が住んでおられるに違いない

    諸人よ、ひざまずいたか
    世界よ、創造主を予感するか
    星空の彼方に神を求めよ
    星々の上に、神は必ず住みたもう
"""
    plainData   = plain.data(using: .utf8, allowLossyConversion: true)!
    cipher      = cryptor.encrypt(plain: plainData)!
    replainData = cryptor.decrypt(cipher: cipher)!
    replain     = String(data: replainData, encoding: .utf8)!

    print("plain       =", plain)
    print("plainData   =", plainData   as NSData)
    print("cipher      =", cipher      as NSData)
    print("replainData =", replainData as NSData)
    print("replain     =", replain)
}


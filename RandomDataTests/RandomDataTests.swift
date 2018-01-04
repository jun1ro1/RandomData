//
//  RandomDataTest.swift
//  RandomDataTest
//
//  Created by OKU Junichirou on 2018/01/03.
//  Copyright (C) 2018 OKU Junichirou. All rights reserved.
//

import XCTest
@testable import RandomData

class RandomDataTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.

        let Primes = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
            31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
            73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
            127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
            179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
            233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
            283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
            353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
            419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
            467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
            547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
            607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
            661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
            739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
            811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
            877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
            947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
            1019, 1021
            ]

        let Deutsch = """
https://ja.wikipedia.org/wiki/歓喜の歌

An die Freude
   Johann Christoph Friedrich von Schiller

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

        let Japanisch = """
https://ja.wikipedia.org/wiki/歓喜の歌

「歓喜に寄せて」
   ヨーハン・クリストフ・フリードリヒ・フォン・シラー

おお友よ、このような音ではない！
我々はもっと心地よい
もっと歓喜に満ち溢れる歌を歌おうではないか

歓喜よ、神々の麗しき霊感よ
天上の楽園の乙女よ
我々は火のように酔いしれて
崇高な汝（歓喜）の聖所に入る

汝が魔力は再び結び合わせる
時流が強く切り離したものを
すべての人々は兄弟となる
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
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        for n in Primes {
            for s: CypherCharacterSet in
                [.DecimalDigits, .UpperCaseLettersSet, .LowerCaseLettersSet, .AlphaNumericsSet,
                 .Base64Set, .ArithmeticCharactersSet, .AlphaNumericSymbolsSet, .AllCharactersSet  ] {
                    guard let str = try? J1RandomData.shared.get(count: n, in: s) else {
                        print("ERROR")
                        continue
                    }
                XCTAssertEqual(str.length, n)
            }
        }
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}

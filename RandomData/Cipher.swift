//
//  Cipher.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/10/22.
//  Copyright (C)
import Foundation

class Cipher {
    let version = 1
    var strSALT: String
    var rounds: UInt32
    var strEncCEK: String
    init() {
        self.strSALT = ""
        self.rounds  = 100000
        self.strEncCEK = ""
    }
    
    func prepare(passPhrase: String) {
        guard let binSALT = J1RandomData.shared.get(count: 16) else {
            return
        }
        self.strSALT = binSALT.base64EncodedString()
        
        let binPASS = passPhrase.data(using: .utf8, allowLossyConversion: true)!
        
        var binKEK = Data(count: Int(kCCKeySizeAES256))
        
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        status =
            binSALT.withUnsafeBytes { ptrSALT in
                binPASS.withUnsafeBytes { ptrPASS in
                    binKEK.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             ptrPASS, binPASS.count,
                                             ptrSALT, binSALT.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK, binKEK.count)
                    }
                }
        }
        print("CCKeyDerivationPBKDF status=", status)
        print("binKEK   =", binKEK as NSData)
        guard status == CCCryptorStatus(kCCSuccess) else {
            return
        }
        
        guard let binCEK = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        var binEncCEK = Data(count: binCEK.count + kCCKeySizeAES256)
        
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        var dataOutMoved = 0
        status =
                binKEK.withUnsafeBytes { ptrKEK in
                    binCEK.withUnsafeBytes { ptrCEK in
                        binEncCEK.withUnsafeMutableBytes { ptrEncCEK in
                            CCCrypt(
                                CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES128),
                                CCOptions(kCCOptionPKCS7Padding),
                                ptrKEK, binKEK.count,
                                nil,
                                ptrCEK, binCEK.count,
                                ptrEncCEK, binEncCEK.count,
                                &dataOutMoved)
                        }
                    }
                }
        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
        print("CCCrypt(Encrypt) status=", status)
        if status == kCCSuccess {
            binEncCEK.removeSubrange(dataOutMoved..<binEncCEK.count)
        }
        self.strEncCEK = binEncCEK.base64EncodedString()
        
        print("binSALT  =", binSALT as NSData)
        print("strSALT  =", self.strSALT)
        print("binKEK   =", binKEK as NSData)

        print("binCEK   =", binCEK as NSData)
        print("binEncCEK=", binEncCEK as NSData)
        print("strEncCEK=", self.strEncCEK)
    }
}



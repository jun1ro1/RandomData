//
//  Cipher.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/10/22.
//  Copyright (C)
import Foundation

class Cipher {
    let version = 1
    var saltStr: String
    var rounds: UInt32
    var encryptedCEK: String
    init() {
        self.saltStr = ""
        self.rounds  = 100000
        self.encryptedCEK = ""
    }
    
    func prepare(passPhrase: String) {
        guard let saltBin = J1RandomData.shared.get(count: 16) else {
            return
        }
        self.saltStr = saltBin.base64EncodedString()
        
        let passBin = passPhrase.data(using: .utf8, allowLossyConversion: true)!
        
        var kekBin = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        let status =
            saltBin.withUnsafeBytes { saltPtr -> Int32 in
                passBin.withUnsafeBytes { passPtr -> Int32 in
                    kekBin.withUnsafeMutableBytes { kekPtr -> Int32 in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             UnsafePointer(passPtr), passBin.count,
                                             UnsafePointer(saltPtr), saltBin.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             UnsafeMutablePointer(kekPtr), kekBin.count)
                    }
                }
            }
        guard status != kCCParamError else {
            return
        }
        
        let kekStr = kekBin.base64EncodedString()
        
        print("status=", status)
        
        guard let ivBin  = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        guard let cekBin = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        var encryptedCekBin = Data(count: cekBin.count + kCCKeySizeAES256)
        
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        var dataMoved = 0
        let keklen = kekBin.count
        let encryptedCekLen = encryptedCekBin.count
        let stat =
            encryptedCekBin.withUnsafeMutableBytes { encryptedCekPtr in
                ivBin.withUnsafeBytes { ivPtr in
                    kekBin.withUnsafeBytes { kekPtr in
                        cekBin.withUnsafeBytes { cekPtr in
                            return CCCrypt(
                                CCOperation(kCCEncrypt),
                                CCAlgorithm(kCCAlgorithmAES128),
                                CCOptions(kCCOptionPKCS7Padding),
                                kekPtr, keklen,
                                ivPtr,
                                cekPtr, cekBin.count,
                                encryptedCekPtr, encryptedCekLen,
                                &dataMoved)
                        }
                    }
                }
            }
        if stat == kCCSuccess {
            encryptedCekBin.removeSubrange(dataMoved..<encryptedCekLen)
        }
        
        print("kekBin=       ", kekBin as NSData)
        print("kekStr=       ", kekStr)

        print("plain     CEK=", cekBin as NSData)
        print("encrypted CEK=", encryptedCekBin as NSData)
        print("stat=", stat)
        //        CCCryptorStatus CCCrypt(
        //            CCOperation op,         /* kCCEncrypt, etc. */
        //            CCAlgorithm alg,        /* kCCAlgorithmAES128, etc. */
        //            CCOptions options,      /* kCCOptionPKCS7Padding, etc. */
        //            const void *key,
        //            size_t keyLength,
        //            const void *iv,         /* optional initialization vector */
        //            const void *dataIn,     /* optional per op and alg */
        //            size_t dataInLength,
        //            void *dataOut,          /* data RETURNED here */
        //            size_t dataOutAvailable,
        //            size_t *dataOutMoved)
        
    }
}



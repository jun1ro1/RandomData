//
//  J1CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

class J1CryptorCore {
    // secitem
    let version = 1
    var strSALT: String
    var rounds: UInt32
    var strEncCEK: String
    
    // instance variables
    var strHshCHECK: String
    var strEncCHECK: String
    init() {
        self.strSALT = ""
        self.rounds  = 100000
        self.strEncCEK = ""
        self.strHshCHECK = ""
        self.strEncCHECK = ""
    }
    
    func encrypt(data plain: Data, with key: Data) -> Data? {
        var cipher = Data(count: plain.count + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                plain.withUnsafeBytes { ptrPlain in
                    cipher.withUnsafeMutableBytes { ptrCipher in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrPlain, plain.count,
                            ptrCipher, cipher.count,
                            &dataOutMoved)
                    }
                }
        }
        print("CCCrypt(Encrypt) status=", status)
        if status == kCCSuccess {
            cipher.removeSubrange(dataOutMoved..<cipher.count)
            return cipher
        }
        else {
            return nil
        }
    }
 
    func decrypt(data cipher: Data, with key: Data) -> Data? {
        var plain = Data(count: cipher.count + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                cipher.withUnsafeBytes { ptrCipher in
                    plain.withUnsafeMutableBytes { ptrPlain in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrCipher, cipher.count,
                            ptrPlain, plain.count,
                            &dataOutMoved)
                    }
                }
        }
        print("CCCrypt(Decrypt) status=", status)
        if status == kCCSuccess {
            plain.removeSubrange(dataOutMoved..<plain.count)
            return plain
        }
        else {
            return nil
        }
    }
    
    func decrypt(base64Encoded cipher: String, with key: Data) -> Data? {
        guard let binCipher = Data(base64Encoded: cipher, options: .ignoreUnknownCharacters) else {
            return nil
        }
        return self.decrypt(data: binCipher, with: key)
    }
    
    func hash(data: Data) -> Data {
        var hashed = Data(count:Int(CC_SHA256_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { ptrData in
            hashed.withUnsafeMutableBytes { ptrHashed in
                CC_SHA256(ptrData, CC_LONG(data.count), ptrHashed)
            }
        }
        return hashed
    }
    
    // MARK: - methods
    func create(password: String) {
        // create SALT
        guard let binSALT = J1RandomData.shared.get(count: 16) else {
            return
        }
        self.strSALT = binSALT.base64EncodedString()
        
        // convert the password to a Data
        let binPASS = password.data(using: .utf8, allowLossyConversion: true)!
        
        // derivate an CEK with the password and the SALT
        var binKEK = Data(count: Int(kCCKeySizeAES256))
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        // https://stackoverflow.com/questions/35749197/how-to-use-common-crypto-and-or-calculate-sha256-in-swift-2-3
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
        
        // create CEK
        guard let binCEK = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        
        // encrypt the CEK with the KEK
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
//        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
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
        
        guard let binCHECK = J1RandomData.shared.get(count: 16) else {
            return
        }
        let hshCHECK = self.hash(data: binCHECK)
        self.strHshCHECK = hshCHECK.base64EncodedString()
        
        print("binCHECK  =", binCHECK as NSData)
        print("hshCHECK  =", hshCHECK as NSData)
        print("strHshCHECK=", self.strHshCHECK)
        
        guard let binEncCHECK = self.encrypt(data: binCHECK, with: binCEK) else {
            return
        }
        self.strEncCHECK = binEncCHECK.base64EncodedString()
        print("binEncCHECK=", binEncCHECK as NSData)
        print("strEncCHECK=", self.strEncCHECK)

    }
    
    func open(password: String) {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        
        // get SALT
        guard let binSALT = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return
        }
        
        // get KEK from SALT, password
        let binPASS = password.data(using: .utf8, allowLossyConversion: true)!
        var binKEK = Data(count: Int(kCCKeySizeAES256))
        print("strSALT  =", self.strSALT)
        print("binSALT  =", binSALT as NSData)
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
        
        // get CEK with KEK
        guard let binCEK = self.decrypt(base64Encoded: self.strEncCEK, with: binKEK) else {
            return
        }
        print("strEncCEK=", self.strEncCEK)
        print("binCEK   =", binCEK as NSData)

        guard let orgHshCHECK = Data(base64Encoded: self.strHshCHECK, options: .ignoreUnknownCharacters) else {
            return
        }
        // get binary CHECK
        guard let binDecCHECK = self.decrypt(base64Encoded: self.strEncCHECK, with: binCEK) else {
            return
        }
        let hshCHECK = self.hash(data: binDecCHECK)
        print("binCEK      =", binCEK as NSData)
        print("orgHshCHECK =", orgHshCHECK as NSData)
        print("hshCHECK    =", hshCHECK as NSData)

        if orgHshCHECK == hshCHECK {
            return
        }
        else {
            return
        }
    }
}


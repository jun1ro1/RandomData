//
//  J1CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

extension Data {
    func encrypt(with key: Data) -> Data? {
        var cipher = Data(count: self.count + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                self.withUnsafeBytes { ptrPlain in
                    cipher.withUnsafeMutableBytes { ptrCipher in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrPlain, self.count,
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

    func decrypt(with key: Data) -> Data? {
        var plain = Data(count: self.count + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status: CCCryptorStatus =
            key.withUnsafeBytes { ptrKey in
                self.withUnsafeBytes { ptrCipher in
                    plain.withUnsafeMutableBytes { ptrPlain in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKey, key.count,
                            nil,
                            ptrCipher, self.count,
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
    
    func hash() -> Data {
        var hashed = Data(count:Int(CC_SHA256_DIGEST_LENGTH))
        _ = self.withUnsafeBytes { ptrData in
            hashed.withUnsafeMutableBytes { ptrHashed in
                CC_SHA256(ptrData, CC_LONG(self.count), ptrHashed)
            }
        }
        return hashed
    }
} // extension Data

extension String {
    func decrypt(with key: Data) -> Data? {
        return Data(base64Encoded: self, options: .ignoreUnknownCharacters)?.decrypt(with: key)
    }
} // extension String

class J1CryptorSession {
    var sessionKey: Data
    var sessionKEK: Data
    
    init(sessionKey: Data, sessionKEK: Data) {
        self.sessionKey = sessionKey
        self.sessionKEK = sessionKEK
    }
}

class J1CryptorCore {
    // secitem
    let version = 1
    var strSALT: String
    var rounds: UInt32
    var strEncCEK: String
    var strHshCHECK: String
    var strEncCHECK: String
    
    // instance variables
    var sessions: [Int: J1CryptorSession]

    static var shared = J1CryptorCore()
    
    init() {
        self.strSALT = ""
        self.rounds  = 100000
        self.strEncCEK = ""
        self.strHshCHECK = ""
        self.strEncCHECK = ""
        self.sessions = [:]
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
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        guard let binEncCEK = binCEK.encrypt(with: binKEK) else {
            return
        }
        self.strEncCEK = binEncCEK.base64EncodedString()

//        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
        print("CCCrypt(Encrypt) status=", status)
        
        print("binSALT  =", binSALT as NSData)
        print("strSALT  =", self.strSALT)
        print("binKEK   =", binKEK as NSData)
        
        print("binCEK   =", binCEK as NSData)
        print("binEncCEK=", binEncCEK as NSData)
        print("strEncCEK=", self.strEncCEK)
        
        guard let binCHECK = J1RandomData.shared.get(count: 16) else {
            return
        }
        let hshCHECK = binCHECK.hash()
        self.strHshCHECK = hshCHECK.base64EncodedString()
        
        print("binCHECK  =", binCHECK as NSData)
        print("hshCHECK  =", hshCHECK as NSData)
        print("strHshCHECK=", self.strHshCHECK)
        
        guard let binEncCHECK = binCHECK.encrypt(with: binCEK) else {
            return
        }
        self.strEncCHECK = binEncCHECK.base64EncodedString()
        print("binEncCHECK=", binEncCHECK as NSData)
        print("strEncCHECK=", self.strEncCHECK)

    }
    
    func open(password: String, cryptor: J1Cryptor) -> Data? {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        
        // get SALT
        guard let binSALT = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return nil
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
            return nil
        }
        
        // get CEK with KEK
        guard let binCEK = self.strEncCEK.decrypt(with: binKEK) else {
            return nil
        }
        print("strEncCEK=", self.strEncCEK)
        print("binCEK   =", binCEK as NSData)

        guard let orgHshCHECK = Data(base64Encoded: self.strHshCHECK, options: .ignoreUnknownCharacters) else {
            return nil
        }
        // get binary CHECK
        guard let binDecCHECK = self.strEncCHECK.decrypt(with: binCEK) else {
            return nil
        }
        let hshCHECK = binDecCHECK.hash()
        print("binCEK      =", binCEK as NSData)
        print("orgHshCHECK =", orgHshCHECK as NSData)
        print("hshCHECK    =", hshCHECK as NSData)

        guard orgHshCHECK == hshCHECK else {
            print("open error")
            return nil
        }
        guard let binSEK = J1RandomData.shared.get(count: kCCKeySizeAES256) else {
            return nil
        }
        guard let binSEKKEK = binKEK.encrypt(with: binSEK) else {
            return nil
        }
        self.sessions[ObjectIdentifier(cryptor).hashValue] =
            J1CryptorSession(sessionKey: binSEK, sessionKEK: binSEKKEK)
        return binSEK
    }
    
    func close(cryptor: J1Cryptor) {
        self.sessions.removeValue(forKey: ObjectIdentifier(cryptor).hashValue)
    }
    
    func encrypt(cryptor: J1Cryptor, plain: Data) -> Data? {
        guard let session = self.sessions[ObjectIdentifier(cryptor).hashValue] else {
            return nil
        }
        guard let kek = session.sessionKEK.decrypt(with: session.sessionKey) else {
            return nil
        }
        guard let key = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        return plain.encrypt(with: key)
    }
    
    func decrypt(cryptor: J1Cryptor, cipher: Data) -> Data? {
        guard let session = self.sessions[ObjectIdentifier(cryptor).hashValue] else {
            return nil
        }
        guard let kek = session.sessionKEK.decrypt(with: session.sessionKey) else {
            return nil
        }
        guard let key = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        return cipher.decrypt(with: key)
    }

}

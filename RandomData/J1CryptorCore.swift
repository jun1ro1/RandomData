
//
//  J1CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

fileprivate func purge(_ data: inout Data?) {
    guard data != nil else {
        return
    }
    data!.resetBytes(in: data!.startIndex..<data!.endIndex)
    data = nil
}

fileprivate func purge(_ str: inout String?) {
    guard str != nil else {
        return
    }
    str!.replaceSubrange(str!.startIndex..<str!.endIndex, with: " ")
    str = nil
}

fileprivate extension Data {
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
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Encrypt) status=", status)
        #endif
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
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Decrypt) status=", status)
        #endif
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

fileprivate extension String {
    func decrypt(with key: Data) -> Data? {
        return Data(base64Encoded: self, options: .ignoreUnknownCharacters)?.decrypt(with: key)
    }
} // extension String

fileprivate class Validator {
    var strHashedMark:    String? = nil
    var strEncryptedMark: String? = nil
    
    init(key: Data) {
        var binMark: Data? = J1RandomData.shared.get(count: 16)
//        defer { purge(&binMark) }
//        defer {
//            if binMark != nil {
//                binMark!.resetBytes(in: binMark!.startIndex..<binMark!.endIndex)
//                binMark = nil
//            }
//        }
        defer {
            binMark!.withUnsafeMutableBytes { ptr in
                ptr[0] = 0

            }
        }

        guard binMark != nil else { return }
        self.strHashedMark = binMark?.hash().base64EncodedString()
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binMark   =", binMark! as NSData)
            print(String(reflecting: type(of: self)), "\(#function) strHshMark=", self.strHashedMark!)
        #endif
        
        var binEncryptedMark: Data? = binMark?.encrypt(with: key)
        defer { purge(&binEncryptedMark) }
        guard binEncryptedMark != nil else { return }
        self.strEncryptedMark = binEncryptedMark?.base64EncodedString()
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncryptedMark=", self.strEncryptedMark!)
        #endif
    }
    
    func validate(key: Data) -> Bool {
        guard self.strHashedMark != nil && self.strEncryptedMark != nil else {
            return false
        }
        
        var hashedMark: Data? = Data(base64Encoded: self.strHashedMark!, options: .ignoreUnknownCharacters)
        defer { purge(&hashedMark) }
        guard hashedMark != nil else { return false }

        // get binary Mark
        var decryptedMark: Data? = self.strEncryptedMark?.decrypt(with: key)
        defer { purge(&decryptedMark) }
        guard decryptedMark != nil else { return false }

        var hashedDecryptedMark: Data? = decryptedMark?.hash()
        defer { purge(&hashedDecryptedMark) }
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) hashedMark          =", hashedMark! as NSData)
            print(String(reflecting: type(of: self)), "\(#function) hashedDecryptedMark =", hashedDecryptedMark! as NSData)
        #endif
        
        return hashedMark == hashedDecryptedMark
    }
} // Validator
    

class J1CryptorCore {
    // secitem
    let version = 1
    var strSALT: String
    var rounds: UInt32
    var strEncCEK: String
    
    // instance variables
    var sessions: [Int: Data]
    fileprivate var validator: Validator?

    static var shared = J1CryptorCore()
    
    init() {
        self.strSALT = ""
        self.rounds  = 100000
        self.strEncCEK = ""
        self.sessions = [:]
        self.validator = nil
    }
    
    // MARK: - methods
    func create(password: String) {
        // create SALT
        var binSALT: Data? = J1RandomData.shared.get(count: 16)
        guard binSALT != nil else { return }
        defer { purge(&binSALT) }
        self.strSALT = binSALT!.base64EncodedString()
        
        // convert the password to a Data
        var binPASS: Data? = password.data(using: .utf8, allowLossyConversion: true)
        defer { purge(&binPASS) }
        guard binPASS != nil else { return }

        // derivate an CEK with the password and the SALT
        var binKEK: Data? = Data(count: Int(kCCKeySizeAES256))
        defer { purge(&binKEK) }
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        // https://stackoverflow.com/questions/35749197/how-to-use-common-crypto-and-or-calculate-sha256-in-swift-2-3
        status =
            binSALT!.withUnsafeBytes { ptrSALT in
                binPASS!.withUnsafeBytes { ptrPASS in
                    binKEK!.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             ptrPASS, binPASS!.count,
                                             ptrSALT, binSALT!.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK, binKEK!.count)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK! as NSData)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            return
        }
        
        // create CEK
        var binCEK: Data? = J1RandomData.shared.get(count: Int(kCCKeySizeAES256))
        defer { purge(&binCEK) }
        guard binCEK != nil else { return }
        self.validator = Validator(key: binCEK!)
        
        // encrypt the CEK with the KEK
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        var binEncCEK: Data? = binCEK?.encrypt(with: binKEK!)
        defer { purge(&binEncCEK) }
        guard binEncCEK != nil else { return }
        self.strEncCEK = binEncCEK!.base64EncodedString()
       
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT! as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK! as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK! as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binEncCEK=", binEncCEK! as NSData)
        #endif
    }
    
    func open(password: String, cryptor: J1Cryptor) -> Data? {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        
        // get SALT
        var binSALT: Data? = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters)
        defer { purge(&binSALT) }
        guard binSALT != nil else { return nil }

        // get KEK from SALT, password
        var binPASS: Data? = password.data(using: .utf8, allowLossyConversion: true)
        defer { purge(&binPASS) }
        guard binPASS != nil else { return nil }

        var binKEK: Data? = Data(count: Int(kCCKeySizeAES256))
        defer { purge(&binKEK) }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strSALT  =", self.strSALT)
            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT! as NSData)
        #endif
        status =
            binSALT!.withUnsafeBytes { ptrSALT in
                binPASS!.withUnsafeBytes { ptrPASS in
                    binKEK!.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             ptrPASS, binPASS!.count,
                                             ptrSALT, binSALT!.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK, binKEK!.count)
                    }
                }
            }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK! as NSData)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            return nil
        }
        
        // get CEK with KEK
        var binCEK: Data? = self.strEncCEK.decrypt(with: binKEK!)
        defer { purge(&binCEK) }
        guard binCEK != nil else { return nil }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncCEK=", self.strEncCEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK! as NSData)
        #endif
        
        // check CEK
        guard self.validator!.validate(key: binCEK!) else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            return nil
        }
        
        var binSEK: Data? = J1RandomData.shared.get(count: kCCKeySizeAES256)
        defer { purge(&binSEK) }
        guard binSEK != nil else { return nil }

        var binKEKEncryptedWithSEK: Data? = binKEK?.encrypt(with: binSEK!)
        defer { purge(&binKEKEncryptedWithSEK) }
        guard binKEKEncryptedWithSEK != nil else { return nil }

        self.sessions[ObjectIdentifier(cryptor).hashValue] = binKEKEncryptedWithSEK!
        return binSEK
    }

    
    func close(cryptor: J1Cryptor) {
        self.sessions.removeValue(forKey: ObjectIdentifier(cryptor).hashValue)
    }
    
    func encrypt(cryptor: J1Cryptor, plain: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        var kek: Data? = self.sessions[ObjectIdentifier(cryptor).hashValue]?.decrypt(with: sek)
        defer { purge(&kek) }
        guard kek != nil else { return nil }

        var cek: Data? = self.strEncCEK.decrypt(with: kek!)
        defer { purge(&cek) }
        guard cek != nil else { return nil }

        return plain.encrypt(with: cek!)
    }
    
    func decrypt(cryptor: J1Cryptor, cipher: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        var kek: Data? = self.sessions[ObjectIdentifier(cryptor).hashValue]?.decrypt(with: sek)
        defer { purge(&kek) }
        guard kek != nil else { return nil }

        var cek: Data? = self.strEncCEK.decrypt(with: kek!)
        defer { purge(&cek) }
        guard cek != nil else { return nil }

        return cipher.decrypt(with: cek!)
    }
}



//
//  J1CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

typealias CryptorKey = NSMutableData

fileprivate extension Data {
    func encrypt(with key: CryptorKey) -> Data? {
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

    func decrypt(with key: CryptorKey) -> Data? {
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

fileprivate extension NSMutableData {
    // Data compatible fucntions
    func withUnsafeBytes<Result>(_ body: (UnsafeRawPointer) -> Result) -> Result {
        let ptr = self.bytes
        return body(ptr)
    }

    func withUnsafeMutableBytes<Result>(_ body: (UnsafeMutableRawPointer) -> Result) -> Result {
        let ptr = self.mutableBytes
        return body(ptr)
    }

    var count: Int {
        return self.length
    }

    func encrypt(with key: CryptorKey) -> NSMutableData? {
        guard let cipher = NSMutableData(length: self.length + kCCKeySizeAES256) else {
            return nil
        }
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
                            ptrPlain, self.length,
                            ptrCipher, cipher.length,
                            &dataOutMoved)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Encrypt) status=", status)
        #endif
        if status == kCCSuccess {
            cipher.length = dataOutMoved
            return cipher
        }
        else {
            return nil
        }
    }

    func decrypt(with key: CryptorKey) -> NSMutableData? {
        guard let plain = NSMutableData(length: self.length + kCCKeySizeAES256) else {
            return nil
        }
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
                            ptrCipher, self.length,
                            ptrPlain, plain.count,
                            &dataOutMoved)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCCrypt(Decrypt) status=", status)
        #endif
        if status == kCCSuccess {
            plain.length = dataOutMoved
            return plain
        }
        else {
            return nil
        }
    }

    func hash() -> NSMutableData {
        // http://developer.hatenastaff.com/entry/swift-3-foundation-data-and-pointer
        let hashed = NSMutableData(length: Int(CC_SHA256_DIGEST_LENGTH))
        _ = self.withUnsafeBytes { ptrData in
            hashed?.withUnsafeMutableBytes { ptrHashed in
                CC_SHA256(ptrData, CC_LONG(self.length), ptrHashed.assumingMemoryBound(to:UInt8.self))
            }
        }
        return hashed!
    }

    func reset() {
        self.resetBytes(in: NSMakeRange(0, self.length))
    }
} // extension NSMutableData

fileprivate extension String {
    func decrypt(with key: CryptorKey) -> CryptorKey? {
        return CryptorKey(base64Encoded: self, options: .ignoreUnknownCharacters)?.decrypt(with: key)
    }
} // extension String

fileprivate class Validator {
    var strHashedMark:    String? = nil
    var strEncryptedMark: String? = nil
    
    init(key: CryptorKey) {
        guard var binMark: CryptorKey = J1RandomData.shared.get(count: 16) else {
            return
        }
        defer { binMark.reset() }

        self.strHashedMark = binMark.hash().base64EncodedString()
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binMark   =", binMark)
            print(String(reflecting: type(of: self)), "\(#function) strHshMark=", self.strHashedMark!)
        #endif
        
        guard var binEncryptedMark: CryptorKey = binMark.encrypt(with: key) else { return }
        defer { binEncryptedMark.reset() }
        self.strEncryptedMark = binEncryptedMark.base64EncodedString()
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncryptedMark=", self.strEncryptedMark!)
        #endif
    }
    
    func validate(key: CryptorKey) -> Bool {
        guard self.strHashedMark != nil && self.strEncryptedMark != nil else {
            return false
        }
        
        guard var hashedMark: CryptorKey
            = NSMutableData(base64Encoded: self.strHashedMark!, options: .ignoreUnknownCharacters) else {
                return false
        }
        defer { hashedMark.reset() }

        // get binary Mark
        guard var decryptedMark: CryptorKey = self.strEncryptedMark?.decrypt(with: key) else {
            return false
        }
        defer { decryptedMark.reset() }

        var hashedDecryptedMark: CryptorKey = decryptedMark.hash()
        defer { hashedDecryptedMark.reset() }
        
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) hashedMark          =", hashedMark)
            print(String(reflecting: type(of: self)), "\(#function) hashedDecryptedMark =", hashedDecryptedMark)
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
    var sessions: [Int: CryptorKey]
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
        guard var binSALT: CryptorKey = J1RandomData.shared.get(count: 16) else { return }
        defer { binSALT.reset() }
        self.strSALT = binSALT.base64EncodedString()
        
        // convert the password to a Data
        guard var binPASS: CryptorKey = password.data(using: .utf8, allowLossyConversion: true)
            as? CryptorKey else {
                return
        }
        defer { binPASS.reset() }

        // derivate an CEK with the password and the SALT
        guard var binKEK: CryptorKey = NSMutableData(length: Int(kCCKeySizeAES256)) else {
            return
        }
        defer { binKEK.reset() }
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
                                             ptrPASS.assumingMemoryBound(to:Int8.self),  binPASS.count,
                                             ptrSALT.assumingMemoryBound(to:UInt8.self), binSALT.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK.assumingMemoryBound(to: UInt8.self), binKEK.count)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            return
        }
        
        // create CEK
        guard var binCEK: CryptorKey = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        defer { binCEK.reset() }
        self.validator = Validator(key: binCEK)
        
        // encrypt the CEK with the KEK
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        guard var binEncCEK: CryptorKey = binCEK.encrypt(with: binKEK) else {
            return
        }
        defer { binEncCEK.reset() }
        self.strEncCEK = binEncCEK.base64EncodedString()
       
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK)
            print(String(reflecting: type(of: self)), "\(#function) binEncCEK=", binEncCEK)
        #endif
    }
    
    func open(password: String, cryptor: J1Cryptor) -> CryptorKey? {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        
        // get SALT
        guard var binSALT: CryptorKey = NSMutableData(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return nil
        }
        defer { binSALT.reset() }

        // get KEK from SALT, password
        guard var binPASS: CryptorKey = password.data(using: .utf8, allowLossyConversion: true) as? CryptorKey else {
            return nil
        }
        defer { binPASS.reset() }

        guard var binKEK: CryptorKey = NSMutableData(length: Int(kCCKeySizeAES256)) else {
            return nil
        }
        defer { binKEK.reset() }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strSALT  =", self.strSALT)
            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT)
        #endif
        status =
            binSALT.withUnsafeBytes { ptrSALT in
                binPASS.withUnsafeBytes { ptrPASS in
                    binKEK.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             ptrPASS.assumingMemoryBound(to: Int8.self),  binPASS.count,
                                             ptrSALT.assumingMemoryBound(to: UInt8.self), binSALT.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK.assumingMemoryBound(to: UInt8.self), binKEK.count)
                    }
                }
            }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            return nil
        }
        
        // get CEK with KEK
        guard var binCEK: CryptorKey = self.strEncCEK.decrypt(with: binKEK) else {
            return nil
        }
        defer { binCEK.reset() }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncCEK=", self.strEncCEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK)
        #endif
        
        // check CEK
        guard self.validator!.validate(key: binCEK) else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            return nil
        }
        
        guard var binSEK: CryptorKey = J1RandomData.shared.get(count: kCCKeySizeAES256) else {
            return nil
        }
        defer { binSEK.reset() }

        guard var binKEKEncryptedWithSEK: CryptorKey = binKEK.encrypt(with: binSEK) else {
            return nil
        }
        defer { binKEKEncryptedWithSEK.reset() }

        self.sessions[ObjectIdentifier(cryptor).hashValue] = binKEKEncryptedWithSEK
        return binSEK
    }

    
    func close(cryptor: J1Cryptor) {
        self.sessions.removeValue(forKey: ObjectIdentifier(cryptor).hashValue)
    }
    
    func encrypt(cryptor: J1Cryptor, plain: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKey = self.sessions[ObjectIdentifier(cryptor).hashValue]?.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKey = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return plain.encrypt(with: cek)
    }
    
    func decrypt(cryptor: J1Cryptor, cipher: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKey = self.sessions[ObjectIdentifier(cryptor).hashValue]?.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKey = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return cipher.decrypt(with: cek)
    }
}



//
//  J1CryptorCore.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/04.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

typealias CryptorKeyType = Data

fileprivate extension Data {
    func encrypt(with key: CryptorKeyType) -> Data? {
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

    func decrypt(with key: CryptorKeyType) -> Data? {
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

    mutating func reset() {
        self.resetBytes(in: self.startIndex..<self.endIndex)
    }
} // extension Data


fileprivate extension String {
    func decrypt(with key: CryptorKeyType) -> CryptorKeyType? {
        return CryptorKeyType(base64Encoded: self, options: .ignoreUnknownCharacters)?.decrypt(with: key)
    }

    func encrypt(with key: CryptorKeyType) -> String? {
        return self.data(using: .utf8, allowLossyConversion: false)?.encrypt(with: key)?.base64EncodedString()
    }

    func decrypt(with key: CryptorKeyType) -> String? {
        guard var data = Data(base64Encoded: self, options: [])?.decrypt(with: key) else {
            return nil
        }
        defer { data.reset() }
        return String(data: data, encoding: .utf8)
    }
} // extension String

fileprivate class Validator {
    var strHashedMark:    String? = nil
    var strEncryptedMark: String? = nil

    init(key: CryptorKeyType) {
        guard var binMark: CryptorKeyType = J1RandomData.shared.get(count: 16) else {
            return
        }
        defer { binMark.reset() }

        self.strHashedMark = binMark.hash().base64EncodedString()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binMark   =", binMark as NSData)
            print(String(reflecting: type(of: self)), "\(#function) strHshMark=", self.strHashedMark!)
        #endif

        guard var binEncryptedMark: CryptorKeyType = binMark.encrypt(with: key) else { return }
        defer { binEncryptedMark.reset() }
        self.strEncryptedMark = binEncryptedMark.base64EncodedString()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncryptedMark=", self.strEncryptedMark!)
        #endif
    }

    func validate(key: CryptorKeyType) -> Bool {
        guard self.strHashedMark != nil && self.strEncryptedMark != nil else {
            return false
        }

        guard var hashedMark
            = CryptorKeyType(base64Encoded: self.strHashedMark!, options: .ignoreUnknownCharacters) else {
                return false
        }
        defer { hashedMark.reset() }

        // get binary Mark
        guard var decryptedMark: CryptorKeyType = self.strEncryptedMark?.decrypt(with: key) else {
            return false
        }
        defer { decryptedMark.reset() }

        var hashedDecryptedMark: CryptorKeyType = decryptedMark.hash()
        defer { hashedDecryptedMark.reset() }

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) hashedMark          =", hashedMark as NSData)
            print(String(reflecting: type(of: self)), "\(#function) hashedDecryptedMark =", hashedDecryptedMark as NSData)
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
    struct Session {
        var cryptor:              J1Cryptor
        var binKEKencryptedBySEK: CryptorKeyType

        init(cryptor: J1Cryptor, key: CryptorKeyType) {
            self.cryptor              = cryptor
            self.binKEKencryptedBySEK = key
        }
    }
    var sessions: [Int: Session]
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
    private func getKEK(password: String, salt: CryptorKeyType) -> CryptorKeyType? {
        // create SALT
        // convert the password to a Data
        guard var binPASS: CryptorKeyType = password.data(using: .utf8, allowLossyConversion: true) else {
            return nil
        }
        defer { binPASS.reset() }

        // derivate an CEK with the password and the SALT
        var binKEK = CryptorKeyType(count: Int(kCCKeySizeAES256))
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        // https://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/CommonCrypto/CommonKeyDerivation.h
        // https://github.com/apportable/CommonCrypto/blob/master/include/CommonCrypto/CommonKeyDerivation.h
        // https://stackoverflow.com/questions/25691613/swift-how-to-call-cckeyderivationpbkdf-from-swift
        // https://stackoverflow.com/questions/35749197/how-to-use-common-crypto-and-or-calculate-sha256-in-swift-2-3
        status =
            salt.withUnsafeBytes { ptrSALT in
                binPASS.withUnsafeBytes { ptrPASS in
                    binKEK.withUnsafeMutableBytes { ptrKEK in
                        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                             ptrPASS, binPASS.count,
                                             ptrSALT, salt.count,
                                             CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                             self.rounds,
                                             ptrKEK, binKEK.count)
                    }
                }
        }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) CCKeyDerivationPBKDF status=", status)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK as NSData)
        #endif
        guard status == CCCryptorStatus(kCCSuccess) else {
            return nil
        }
        return binKEK
    }

    func create(password: String) {
        // create SALT
        guard var binSALT: CryptorKeyType = J1RandomData.shared.get(count: 16) else { return }
        defer { binSALT.reset() }

        // convert the password to a Data
        guard var binPASS: CryptorKeyType = password.data(using: .utf8, allowLossyConversion: true) else {
                return
        }
        defer { binPASS.reset() }

        // derivate a KEK with the password and the SALT
        guard let binKEK = self.getKEK(password: password, salt: binSALT) else {
            return
        }

        // create a CEK
        guard var binCEK: CryptorKeyType = J1RandomData.shared.get(count: Int(kCCKeySizeAES256)) else {
            return
        }
        defer { binCEK.reset() }
        self.validator = Validator(key: binCEK)

        // encrypt the CEK with the KEK
        // https://stackoverflow.com/questions/25754147/issue-using-cccrypt-commoncrypt-in-swift
        // https://stackoverflow.com/questions/37680361/aes-encryption-in-swift
        guard var binEncCEK: CryptorKeyType = binCEK.encrypt(with: binKEK) else {
            return
        }
        defer { binEncCEK.reset() }

        // store a salt and an encrypted CEK
        self.strSALT = binSALT.base64EncodedString()
        self.strEncCEK = binEncCEK.base64EncodedString()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binSALT  =", binSALT as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binKEK   =", binKEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binEncCEK=", binEncCEK as NSData)
        #endif
    }

    func open(password: String, cryptor: J1Cryptor) -> CryptorKeyType? {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)

        // get SALT
        guard var binSALT = CryptorKeyType(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return nil
        }
        defer { binSALT.reset() }

        // get KEK from SALT, password
        guard var binKEK = self.getKEK(password: password, salt: binSALT) else {
            return nil
        }
        defer { binKEK.reset() }

        // get CEK with KEK
        guard var binCEK: CryptorKeyType = self.strEncCEK.decrypt(with: binKEK) else {
            return nil
        }
        defer { binCEK.reset() }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncCEK=", self.strEncCEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK as NSData)
        #endif

        // check CEK
        guard self.validator?.validate(key: binCEK) == true else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            return nil
        }

        guard var binSEK: CryptorKeyType = J1RandomData.shared.get(count: kCCKeySizeAES256) else {
            return nil
        }
        defer { binSEK.reset() }

        guard var binKEKEncryptedWithSEK: CryptorKeyType = binKEK.encrypt(with: binSEK) else {
            return nil
        }
        defer { binKEKEncryptedWithSEK.reset() }

        self.sessions[ObjectIdentifier(cryptor).hashValue] = Session(cryptor: cryptor, key: binKEKEncryptedWithSEK)
        return binSEK
    }


    func close(cryptor: J1Cryptor) {
        self.sessions.removeValue(forKey: ObjectIdentifier(cryptor).hashValue)
    }

    func change(password oldpass: String, to newpass: String) -> Bool? {
        // get SALT
        guard var binSALT = CryptorKeyType(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return nil
        }
        defer { binSALT.reset() }

        // get KEK from SALT, password
        guard var binKEK = self.getKEK(password: oldpass, salt: binSALT) else {
            return nil
        }
        defer { binKEK.reset() }

        // get CEK with KEK
        guard var binCEK: CryptorKeyType = self.strEncCEK.decrypt(with: binKEK) else {
            return nil
        }
        defer { binCEK.reset() }
        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) strEncCEK=", self.strEncCEK)
            print(String(reflecting: type(of: self)), "\(#function) binCEK   =", binCEK as NSData)
        #endif

        // check CEK
        guard self.validator?.validate(key: binCEK) == true else {
            #if DEBUG
                print(String(reflecting: type(of: self)), "\(#function) validate= false")
            #endif
            return nil
        }

        // change KEK
        guard var binNewKEK = self.getKEK(password: newpass, salt: binSALT) else {
            return nil
        }
        defer { binNewKEK.reset() }

        // crypt a CEK with a new KEK
        guard var binNewEncCEK: CryptorKeyType = binCEK.encrypt(with: binNewKEK) else {
            return nil
        }
        defer { binNewEncCEK.reset() }

        // store a new encrypted CEK
        self.strEncCEK = binNewEncCEK.base64EncodedString()

        #if DEBUG
            print(String(reflecting: type(of: self)), "\(#function) binNewKEK    =", binNewKEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binCEK       =", binCEK as NSData)
            print(String(reflecting: type(of: self)), "\(#function) binNewEncCEK =", binNewEncCEK as NSData)
        #endif

//        // replace a KEK encrypted with the SEK
//        self.sessions.keys.forEach { (ci) in
//            guard let cryptor = self.sessions[ci]?.cryptor else {
//                return
//            }
//            guard let binSEK = cryptor.key else {
//                return
//            }
//            guard let binKEKEncryptedWithSEK: CryptorKeyType = binNewKEK.encrypt(with: binSEK) else {
//                return
//            }
//            self.sessions.updateValue(Session(cryptor: cryptor, key: binKEKEncryptedWithSEK), forKey: ci)
//        }

        return true
    }

    func encrypt(cryptor: J1Cryptor, plain: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKeyType =
            self.sessions[ObjectIdentifier(cryptor).hashValue]?.binKEKencryptedBySEK.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKeyType = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return plain.encrypt(with: cek)
    }

    func decrypt(cryptor: J1Cryptor, cipher: Data) -> Data? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKeyType =
            self.sessions[ObjectIdentifier(cryptor).hashValue]?.binKEKencryptedBySEK.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKeyType = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return cipher.decrypt(with: cek)
    }

    func encrypt(cryptor: J1Cryptor, plain: String) -> String? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKeyType =
            self.sessions[ObjectIdentifier(cryptor).hashValue]?.binKEKencryptedBySEK.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKeyType = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return plain.encrypt(with: cek)
    }

    func decrypt(cryptor: J1Cryptor, cipher: String) -> String? {
        guard let sek = cryptor.key else {
            return nil
        }
        guard var kek: CryptorKeyType =
            self.sessions[ObjectIdentifier(cryptor).hashValue]?.binKEKencryptedBySEK.decrypt(with: sek) else {
            return nil
        }
        defer { kek.reset() }

        guard var cek: CryptorKeyType = self.strEncCEK.decrypt(with: kek) else {
            return nil
        }
        defer { cek.reset() }

        return cipher.decrypt(with: cek)
    }
}


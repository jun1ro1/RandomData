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
    
    var strHshCHECK: String
    var strEncCHECK: String
    init() {
        self.strSALT = ""
        self.rounds  = 100000
        self.strEncCEK = ""
        self.strHshCHECK = ""
        self.strEncCHECK = ""
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
        
        guard let binCHECK = J1RandomData.shared.get(count: 16) else {
            return
        }
        var hshCHECK = Data(count:Int(CC_SHA256_DIGEST_LENGTH))
        _ = binCHECK.withUnsafeBytes { ptrCHECK in
            hshCHECK.withUnsafeMutableBytes { ptrHSH in
                CC_SHA256(ptrCHECK, CC_LONG(binCHECK.count), ptrHSH)
            }
        }
        self.strHshCHECK = hshCHECK.base64EncodedString()
    }

    func open(password: String) {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        guard let binSALT = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return
        }
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
        
        guard  let binEncCEK = Data(base64Encoded: self.strEncCEK, options: .ignoreUnknownCharacters) else {
            return
        }
        var binCEK    = Data(count: kCCKeySizeAES256 + kCCKeySizeAES256)
        var dataOutMoved = 0
        status =
            binKEK.withUnsafeBytes { ptrKEK in
                binEncCEK.withUnsafeBytes { ptrEncCEK in
                    binCEK.withUnsafeMutableBytes { ptrCEK in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKEK, binKEK.count,
                            nil,
                            ptrEncCEK, binEncCEK.count,
                            ptrCEK, binCEK.count,
                            &dataOutMoved)
                    }
                }
        }
        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
        print("CCCrypt(Decrypt) status=", status)
        if status == kCCSuccess {
            binCEK.removeSubrange(dataOutMoved..<binCEK.count)
        }
        
        print("binKEK   =", binKEK as NSData)
        print("binCEK   =", binCEK as NSData)
        print("strEncCEK=", self.strEncCEK)
        print("binEncCEK=", binEncCEK as NSData)
    }

    // MARK: - old version
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
    

    func restore(passPhrase: String) {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        guard let binSALT = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return
        }
        let binPASS = passPhrase.data(using: .utf8, allowLossyConversion: true)!
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
        
        guard  let binEncCEK = Data(base64Encoded: self.strEncCEK, options: .ignoreUnknownCharacters) else {
            return
        }
        var binCEK    = Data(count: kCCKeySizeAES256 + kCCKeySizeAES256)
        var dataOutMoved = 0
        status =
            binKEK.withUnsafeBytes { ptrKEK in
                binEncCEK.withUnsafeBytes { ptrEncCEK in
                    binCEK.withUnsafeMutableBytes { ptrCEK in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKEK, binKEK.count,
                            nil,
                            ptrEncCEK, binEncCEK.count,
                            ptrCEK, binCEK.count,
                            &dataOutMoved)
                    }
                }
        }
        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
        print("CCCrypt(Decrypt) status=", status)
        if status == kCCSuccess {
            binCEK.removeSubrange(dataOutMoved..<binCEK.count)
        }
        
        print("binKEK   =", binKEK as NSData)
        print("binCEK   =", binCEK as NSData)
        print("strEncCEK=", self.strEncCEK)
        print("binEncCEK=", binEncCEK as NSData)
    }
 
    func withCEK(passPhrase: String, _ closure:(_ cek: Data) -> Data) -> Data? {
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        guard let binSALT = Data(base64Encoded: self.strSALT, options: .ignoreUnknownCharacters) else {
            return nil
        }
        let binPASS = passPhrase.data(using: .utf8, allowLossyConversion: true)!
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
        
        guard  let binEncCEK = Data(base64Encoded: self.strEncCEK, options: .ignoreUnknownCharacters) else {
            return nil
        }
        var binCEK    = Data(count: kCCKeySizeAES256 + kCCKeySizeAES256)
        var dataOutMoved = 0
        status =
            binKEK.withUnsafeBytes { ptrKEK in
                binEncCEK.withUnsafeBytes { ptrEncCEK in
                    binCEK.withUnsafeMutableBytes { ptrCEK in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrKEK, binKEK.count,
                            nil,
                            ptrEncCEK, binEncCEK.count,
                            ptrCEK, binCEK.count,
                            &dataOutMoved)
                    }
                }
        }
        binKEK.resetBytes(in: binKEK.startIndex..<binKEK.endIndex)
        print("CCCrypt(Decrypt) status=", status)
        if status == kCCSuccess {
            binCEK.removeSubrange(dataOutMoved..<binCEK.count)
        }
        
        print("binKEK   =", binKEK as NSData)
        print("binCEK   =", binCEK as NSData)
        print("strEncCEK=", self.strEncCEK)
        print("binEncCEK=", binEncCEK as NSData)
        
        let result = closure(binCEK)
        
        binCEK.resetBytes(in: binCEK.startIndex..<binCEK.endIndex)
        return result
    }

    func encrypt(CEK binCEK: Data, _ data: Data) -> Data? {
        guard 0 < data.count && data.count <= kCCBlockSizeAES128 else {
            return nil
        }
        var binEncData = Data(count: kCCKeySizeAES256 + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status =
            data.withUnsafeBytes { ptrData in
                binCEK.withUnsafeBytes { ptrCEK in
                    binEncData.withUnsafeMutableBytes { ptrEncData in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrCEK, binCEK.count,
                            nil,
                            ptrData, data.count,
                            ptrEncData, binEncData.count,
                            &dataOutMoved)
                    }
                }
        }
        print("CCCrypt(Encrypt) status=", status)
        if status == kCCSuccess {
            binEncData.removeSubrange(dataOutMoved..<binEncData.count)
        }
        return binEncData
    }
 
    func decrypt(CEK binCEK: Data, _ data: Data) -> Data? {
        guard 0 < data.count && data.count <= kCCKeySizeAES256 + kCCKeySizeAES256 else {
            return nil
        }
        var binEncData = Data(count: kCCKeySizeAES256 + kCCKeySizeAES256)
        var dataOutMoved = 0
        let status =
            data.withUnsafeBytes { ptrData in
                binCEK.withUnsafeBytes { ptrCEK in
                    binEncData.withUnsafeMutableBytes { ptrEncData in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            CCOptions(kCCOptionPKCS7Padding),
                            ptrCEK, binCEK.count,
                            nil,
                            ptrData, data.count,
                            ptrEncData, binEncData.count,
                            &dataOutMoved)
                    }
                }
        }
        print("CCCrypt(Decrypt) status=", status)
        if status == kCCSuccess {
            binEncData.removeSubrange(dataOutMoved..<binEncData.count)
        }
        return binEncData
    }

}



//
//  J1Cryptor.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/05.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

class J1Cryptor {
    static var core: J1CryptorCore = J1CryptorCore.shared
    var key: Data?
    
    init() {
        self.key = nil
    }
    
    func open(password: String) {
        self.key = J1Cryptor.core.open(password: password, cryptor: self)
    }
    
    func close() {
        J1Cryptor.core.close(cryptor: self)
        self.key = nil
    }
    
    func encrypt(plain: Data) -> Data? {
        guard self.key != nil else {
            return nil
        }
        return J1Cryptor.core.encrypt(cryptor: self, plain: plain)
    }

    func decrypt(cipher: Data) -> Data? {
        guard self.key != nil else {
            return nil
        }
        return J1Cryptor.core.decrypt(cryptor: self, cipher: cipher)
    }
}

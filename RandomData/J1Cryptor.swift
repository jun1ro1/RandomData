//
//  J1Cryptor.swift
//  RandomData
//
//  Created by OKU Junichirou on 2017/11/05.
//  Copyright (C) 2017 OKU Junichirou. All rights reserved.
//

import Foundation

class J1Cryptor {
    var core: J1CryptorCore
    var sessionKey: Data?
    
    init() {
        self.core = J1CryptorCore.shared
        self.sessionKey = nil
    }
    
    func open(password: String) {
        self.sessionKey = self.core.open(password: password, cryptor: self)
    }
    
    func close() {
        self.core.close(cryptor: self)
        self.sessionKey = nil
    }
    
    func encrypt(plain: Data) -> Data? {
        guard self.sessionKey != nil else {
            return nil
        }
        return self.core.encrypt(cryptor: self, plain: plain)
    }

    func decrypt(cipher: Data) -> Data? {
        guard self.sessionKey != nil else {
            return nil
        }
        return self.core.decrypt(cryptor: self, cipher: cipher)
    }
}

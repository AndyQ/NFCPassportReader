//
//  PassportDetails.swift
//  SwiftUITest
//
//  Created by Andy Qua on 30/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader

class PassportDetails : ObservableObject {
    @Published var passportNumber : String = UserDefaults.standard.string(forKey:"passportNumber" ) ?? ""
    @Published var dateOfBirth: String = UserDefaults.standard.string(forKey:"dateOfBirth" ) ?? ""
    @Published var expiryDate: String = UserDefaults.standard.string(forKey:"expiryDate" ) ?? ""
    @Published var passport : NFCPassportModel?
    
    var isValid : Bool {
        return passportNumber.count >= 8 && dateOfBirth.count == 6 && expiryDate.count == 6
    }
    
    func getMRZKey() -> String {
        let d = UserDefaults.standard
        d.set(passportNumber, forKey: "passportNumber")
        d.set(dateOfBirth, forKey: "dateOfBirth")
        d.set(expiryDate, forKey: "expiryDate")
        
        return NFCKeyUtils.instance.getMRZKey(idNumber: passportNumber, birthDate: dateOfBirth, cardExpiryDate: expiryDate)
    }

}


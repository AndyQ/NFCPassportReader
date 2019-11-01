//
//  Passport.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 30/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import NFCPassportReader


public struct Passport {
    public var documentType : String
    public var documentSubType : String
    public var personalNumber : String
    public var documentNumber : String
    public var issuingAuthority : String
    public var documentExpiryDate : String
    public var firstName : String
    public var lastName : String
    public var dateOfBirth : String
    public var gender : String
    public var nationality : String
    public var image : UIImage
    
    public var passportSigned : Bool = false
    public var passportDataValid : Bool = false
    
    init( fromNFCPassportModel model : NFCPassportModel ) {
        self.image = model.passportImage ?? UIImage(named:"head")!

        documentType = model.documentType
        documentSubType = model.documentSubType
        
        issuingAuthority = model.issuingAuthority
        documentNumber = model.documentNumber
        nationality = model.nationality
        dateOfBirth = model.dateOfBirth
        gender = model.gender
        documentExpiryDate = model.documentExpiryDate
        personalNumber = model.personalNumber
        lastName = model.lastName
        firstName = model.firstName
        
        // Check whether a genuine passport or not
        let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!
        _ = model.verifyPassport( masterListURL: masterListURL )
        self.passportSigned = model.passportCorrectlySigned
        self.passportDataValid = model.passportDataValid
    }
    
    init( passportMRZData: String, image : UIImage, signed:Bool, dataValid:Bool ) {
        
        self.image = image
        self.passportSigned = signed
        self.passportDataValid = dataValid
        let line1 = passportMRZData[0..<44]
        let line2 = passportMRZData[44...]
        
        // Line 1
        documentType = line1[0..<1]
        documentSubType = line1[1..<2]
        issuingAuthority = line1[2..<5]
        
        let names = line1[5..<44].components(separatedBy: "<<")
        lastName = names[0].replacingOccurrences(of: "<", with: " " )
        
        var name = ""
        if names.count > 1 {
            let fn = names[1].replacingOccurrences(of: "<", with: " " ).strip()
            name += fn + " "
        }
        firstName = name.strip()
        
        
        // Line 2
        documentNumber = line2[0..<9].replacingOccurrences(of: "<", with: "" )
        nationality = line2[10..<13]
        dateOfBirth = line2[13..<19]
        gender = line2[20..<21]
        documentExpiryDate = line2[21..<27]
        personalNumber = line2[28..<42].replacingOccurrences(of: "<", with: "" )
    }
}

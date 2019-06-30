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
    public var errors : [Error] = []
    
    init( fromNFCPassportModel model : NFCPassportModel ) {
        self.image = model.passportImage ?? UIImage(named:"head")!
        
        let elements = model.passportDataElements ?? [:]
        
        print( elements )
        let type = elements["5F03"]
        documentType = type?[0] ?? "?"
        documentSubType = type?[1] ?? "?"
        
        issuingAuthority = elements["5F28"] ?? "?"
        documentNumber = (elements["5A"] ?? "?").replacingOccurrences(of: "<", with: "" )
        nationality = elements["5F2C"] ?? "?"
        dateOfBirth = elements["5F57"]  ?? "?"
        gender = elements["5F35"] ?? "?"
        documentExpiryDate = elements["59"] ?? "?"
        personalNumber = (elements["53"] ?? "?").replacingOccurrences(of: "<", with: "" )
        
        let names = (elements["5B"] ?? "?").components(separatedBy: "<<")
        lastName = names[0].replacingOccurrences(of: "<", with: " " )
        
        var name = ""
        if names.count > 1 {
            let fn = names[1].replacingOccurrences(of: "<", with: " " ).strip()
            name += fn + " "
        }
        firstName = name.strip()
        
        
        // Check whether a genuine passport or not
        
        // Two Parts:
        // Part 1 - Has the SOD (Security Object Document) been signed by a valid country signing certificate authority (CSCA)?
        // Part 2 - has it been tampered with (e.g. hashes of Datagroups match those in the SOD?
        guard let sod = model.getDataGroup(.SOD) else { return }
        
        guard let dg1 = model.getDataGroup(.DG1),
            let dg2 = model.getDataGroup(.DG2) else { return }
        
        
        // Validate passport
        let pa =  PassiveAuthentication()
        
        do {
            try pa.checkPassportCorrectlySigned( sodBody : sod.body )
            self.passportSigned = true
        } catch let error {
            self.passportSigned = false
            errors.append( error )
        }
        
        do {
            try pa.checkDataNotBeenTamperedWith( sodBody : sod.body, dataGroupsToCheck: [.DG1:dg1, .DG2:dg2] )
            self.passportDataValid = true
        } catch let error {
            self.passportDataValid = false
            errors.append( error )
        }
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

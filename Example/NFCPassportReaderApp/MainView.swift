//
//  MainView.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader


class PassportDetails : BindableObject {
    var didChange = PassthroughSubject<Void, Never>()
    
    var passportNumber : String = UserDefaults.standard.string(forKey:"passportNumber" ) ?? "" { didSet { update() } }
    var dateOfBirth: String = UserDefaults.standard.string(forKey:"dateOfBirth" ) ?? "" { didSet { update() } }
    var expiryDate: String = UserDefaults.standard.string(forKey:"expiryDate" ) ?? "" { didSet { update() } }
    
    var isValid : Bool {
        return passportNumber.count >= 8 && dateOfBirth.count == 6 && expiryDate.count == 6
    }
    
    func update() {
        didChange.send(())
    }
    
    func getMRZKey() -> String {
        let d = UserDefaults.standard
        d.set(passportNumber, forKey: "passportNumber")
        d.set(dateOfBirth, forKey: "dateOfBirth")
        d.set(expiryDate, forKey: "expiryDate")
        
        // Calculate checksums
        let passportNrChksum = calcCheckSum(passportNumber)
        let dateOfBirthChksum = calcCheckSum(dateOfBirth)
        let expiryDateChksum = calcCheckSum(expiryDate)
        
        let mrzKey = "\(passportNumber)\(passportNrChksum)\(dateOfBirth)\(dateOfBirthChksum)\(expiryDate)\(expiryDateChksum)"
        
        return mrzKey
    }
    
    func calcCheckSum( _ checkString : String ) -> Int {
        let characterDict  = ["0" : "0", "1" : "1", "2" : "2", "3" : "3", "4" : "4", "5" : "5", "6" : "6", "7" : "7", "8" : "8", "9" : "9", "<" : "0", " " : "0", "A" : "10", "B" : "11", "C" : "12", "D" : "13", "E" : "14", "F" : "15", "G" : "16", "H" : "17", "I" : "18", "J" : "19", "K" : "20", "L" : "21", "M" : "22", "N" : "23", "O" : "24", "P" : "25", "Q" : "26", "R" : "27", "S" : "28","T" : "29", "U" : "30", "V" : "31", "W" : "32", "X" : "33", "Y" : "34", "Z" : "35"]
        
        var sum = 0
        var m = 0
        let multipliers : [Int] = [7, 3, 1]
        for c in checkString {
            guard let lookup = characterDict["\(c)"],
                let number = Int(lookup) else { return 0 }
            let product = number * multipliers[m]
            sum += product
            m = (m+1) % 3
        }
        
        return (sum % 10)
    }
}


struct MainView : View {
    @ObjectBinding var passportDetails = PassportDetails()
    @State private var showingAlert = false
    @State private var showDetails = false
    @State private var alertTitle : String = ""
    @State private var alertMessage : String = ""
    
    @State private var passportData : String = ""
    @State private var passportImage : UIImage? = nil

    let passportReader = PassportReader()

    var body: some View {
        
        ZStack {
            VStack {
                Text( "Enter passport details" )
                    .font(.title)
                    .padding()
                
                TextField($passportDetails.passportNumber, placeholder: Text("Passport number"))
                    .textContentType(.name)
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($passportDetails.dateOfBirth, placeholder: Text("Date of birth"))
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($passportDetails.expiryDate, placeholder: Text("Passport expiry date"))
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                Spacer()
                }.padding( .top )
            VStack {
                Spacer()
                
                Button(action: {
                    self.scanPassport( mrzKey: self.passportDetails.getMRZKey() )
                }) {
                    Text("Scan Passport")
                        .font(.largeTitle)
                        .color(passportDetails.isValid ? .secondary : Color.secondary.opacity(0.25))
                    } .disabled( !passportDetails.isValid )
                Spacer()
            }
        }.presentation($showingAlert) {
            Alert(title: Text(alertTitle), message:
                Text(alertMessage), dismissButton: .default(Text("Got it!")))
            }.presentation(showDetails ? Modal(DetailView(shouldDismiss: $showDetails, mrzData: passportData, image: passportImage), onDismiss:{ self.showDetails = false }) : nil)

    }
    
    
    func scanPassport( mrzKey: String ) {
        let dataGroups : [DataGroupId] = [.COM, .DG1, .DG2, .SOD]

        passportReader.readPassport(mrzKey: mrzKey, tags: dataGroups, completed: { (error) in
            if let error = error {
                switch error {
                case .NFCNotSupported:
                    self.alertTitle = "Scanning Not Supported"
                    self.alertMessage = "This device doesn't support tag scanning."
                case .ResponseError(let val):
                    self.alertTitle = "Error reading tag"
                    self.alertMessage = "There was an error reading the tag - \(val)."
                default:
                    self.alertTitle = "Problem reading passport"
                    self.alertMessage = "\(error)"
                }
                
                self.showingAlert = true
            } else {
                self.passportData = self.passportReader.passportMRZ
                self.passportImage = self.passportReader.passportImage
                self.showDetails = true
            }
        })
    }
}

#if DEBUG
struct MainView_Previews : PreviewProvider {
    static var previews: some View {
        Group {
            MainView().environment( \.colorScheme, .dark)
            MainView().environment( \.colorScheme, .light)
        }
    }
}
#endif

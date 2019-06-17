//
//  ContentView.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import NFCPassportReader

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


struct MainView : View {
    @State private var passportNumber: String = UserDefaults.standard.string(forKey:"passportNumber" ) ?? ""
    @State private var dateOfBirth: String = UserDefaults.standard.string(forKey:"dateOfBirth" ) ?? ""
    @State private var expiryDate: String = UserDefaults.standard.string(forKey:"expiryDate" ) ?? ""
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
                
                TextField($passportNumber, placeholder: Text("Passport number"))
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($dateOfBirth, placeholder: Text("Date of birth"))
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($expiryDate, placeholder: Text("Passport expiry date"))
                    .foregroundColor(Color.primary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                Spacer()
                }.padding( .top )
            VStack {
                Spacer()
                
                Button(action: {
                    self.scanPassport()
                }) {
                    Text("Scan Passport")
                        .foregroundColor(Color.secondary)
                        .font(.largeTitle)

                }
                Spacer()
            }
        }.presentation($showingAlert) {
            Alert(title: Text(alertTitle), message:
                Text(alertMessage), dismissButton: .default(Text("Got it!")))
            }.presentation(showDetails ? Modal(DetailView(shouldDismiss: $showDetails, mrzData: passportData, image: passportImage), onDismiss:{ self.showDetails = false }) : nil)

    }
    
    
    func scanPassport() {
        let d = UserDefaults.standard
        d.set(passportNumber, forKey: "passportNumber")
        d.set(dateOfBirth, forKey: "dateOfBirth")
        d.set(expiryDate, forKey: "expiryDate")
        
        // Calculate checksums
        let passportNrChksum = calcCheckSum(passportNumber)
        let dateOfBirthChksum = calcCheckSum(dateOfBirth)
        let expiryDateChksum = calcCheckSum(expiryDate)
        
        let mrzKey = "\(passportNumber)\(passportNrChksum)\(dateOfBirth)\(dateOfBirthChksum)\(expiryDate)\(expiryDateChksum)"
        
        passportReader.readPassport(mrzKey: mrzKey, tags: [.COM, .DG1, .DG2], completed: { (error) in
            if let error = error {
                if error == .NFCNotSupported {
                    self.alertTitle = "Scanning Not Supported"
                    self.alertMessage = "This device doesn't support tag scanning."
                } else {
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
struct ContentView_Previews : PreviewProvider {
    static var previews: some View {
        MainView()
    }
}
#endif

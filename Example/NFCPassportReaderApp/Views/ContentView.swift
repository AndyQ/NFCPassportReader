//
//  ContentView.swift
//  SwiftUITest
//
//  Created by Andy Qua on 04/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader

// A View that just uses the UIColor systemBackground allowing
// For light.dark mode support - willo be removed once this makes its way into SwiftUI properly
struct BackgroundView : UIViewRepresentable {
    
    var color: UIColor = .systemBackground
    
    func makeUIView(context: Context) -> UIView {
        UIView(frame: .zero)
    }
    
    func updateUIView(_ view: UIView, context: Context) {
        view.backgroundColor = color
    }
}



struct ContentView : View {
    @EnvironmentObject var passportDetails: PassportDetails

    @State private var showingAlert = false
    @State private var showDetails = false
    @State private var alertTitle : String = ""
    @State private var alertMessage : String = ""
    
    private let passportReader = PassportReader()
    
    var body: some View {
        ZStack {
            VStack {
                
                Text( "Enter passport details" )
                    .foregroundColor(Color.secondary)
                    .font(.title)
                    .padding(0.0)
                
                TextField($passportDetails.passportNumber, placeholder: Text("Passport number"))
                    .textContentType(.name)
                    .foregroundColor(Color.secondary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($passportDetails.dateOfBirth, placeholder: Text("Date of birth"))
                    .foregroundColor(Color.secondary)
                    .textFieldStyle(.roundedBorder)
                    .padding([.leading, .trailing])
                
                TextField($passportDetails.expiryDate, placeholder: Text("Passport expiry date"))
                    .foregroundColor(Color.secondary)
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
                        .font(.largeTitle)
                        .color(passportDetails.isValid ? .secondary : Color.secondary.opacity(0.25))
                    }
                    .disabled( !passportDetails.isValid )
                Spacer()
            }
            
            PassportView()
                .frame(width: UIScreen.main.bounds.width-20, height: 220)
                .offset(y: showDetails ? 0 : UIScreen.main.bounds.height + 100)
                .animation(.basic(duration: 0.3, curve: .easeInOut))
                .tapAction {
                    self.showDetails.toggle()
            }

        }.presentation($showingAlert) {
                Alert(title: Text(alertTitle), message:
                    Text(alertMessage), dismissButton: .default(Text("Got it!")))
    }
     .background(BackgroundView())
    }
}

extension ContentView {
    func scanPassport( ) {
        let mrzKey = self.passportDetails.getMRZKey()

        
        let dataGroups : [DataGroupId] = [.COM, .DG1, .DG2, .SOD]
        passportReader.readPassport(mrzKey: mrzKey, tags: dataGroups, completed: { (passport, error) in
            if let passport = passport {
                // All good, we got a passport
                let passportModel = Passport( fromNFCPassportModel: passport)

                DispatchQueue.main.async {
                    self.passportDetails.passport = passportModel
                    self.showDetails.toggle()
                }

            } else {
                self.alertTitle = "Oops"
                self.alertTitle = "\(error?.localizedDescription ?? "Unknown error")"
                self.showingAlert = true

            }
        })

    }
}

#if DEBUG
struct ContentView_Previews : PreviewProvider {

    static var previews: some View {
        let pptData = "P<GBRTEST<<TEST<TEST<<<<<<<<<<<<<<<<<<<<<<<<1234567891GBR8001019M2106308<<<<<<<<<<<<<<04"
        let passport = Passport( passportMRZData: pptData, image:UIImage(named: "head")!, signed: true, dataValid: true )
        let pd = PassportDetails()
        pd.passport = passport
        
        return Group {
            ContentView().environment( \.colorScheme, .light).environmentObject(pd)
            ContentView().environment( \.colorScheme, .dark).environmentObject(pd)
        }
    }
}
#endif



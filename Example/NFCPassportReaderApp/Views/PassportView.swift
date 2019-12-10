
//
//  PassportView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 30/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import NFCPassportReader

// Outline view of passport
struct PassportView : View {
    @ObservedObject var passportDetails: PassportDetails
    
    var body: some View {
        let passport = passportDetails.passport
        return HStack {
            if (passport) != nil {
                
                ZStack(alignment: .bottomTrailing) {
                    PassportDetailsView(passportDetails: passportDetails)
                    
                    HStack {
                        if !passport!.passportDataNotTampered {
                            VStack {
                                Image( systemName:"exclamationmark").foregroundColor(.red)
                                    .font(.system(size: 50))
                                    .padding(.bottom, 5)
                                
                                Text( "Tampered")
                                    .font(.caption)
                                    .foregroundColor(.red)
                            }
                            
                        }
                        VStack(alignment: .center) {
                            if passport!.passportCorrectlySigned && passport!.documentSigningCertificateVerified {
                                Image( systemName:"checkmark.seal").foregroundColor(.green)
                                    .font(.system(size: 50))
                                    .padding(.bottom, 5)
                                Text( "Genuine")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            } else {
                                Image( systemName:"xmark.seal").foregroundColor(.red)
                                    .font(.system(size: 50))
                                    .padding([.leading,.trailing], 15)
                                    .padding(.bottom, 5)
                                Text( "Not Genuine")
                                    .font(.caption)
                                    .foregroundColor(.red)
                                    .frame(minWidth: 0, maxWidth: 100, minHeight: 0, maxHeight: 22)
                            }
                        }

                    }.padding( [.trailing, .bottom], 10)
                }
            } else {
                Text( "No Passport set").padding()
            }
        }
        .background( Color.primary.colorInvert() )
        .cornerRadius(10)
        .shadow(radius: 20)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.primary, lineWidth: 2)
        )

    }
}


// Shows the Pzssport details
struct PassportDetailsView : View {
    @ObservedObject var passportDetails: PassportDetails
    
    var body: some View {
        let passport = passportDetails.passport
        return HStack(alignment: .top) {
            VStack(alignment: .leading) {
                Spacer()
                Image(uiImage:passport!.passportImage ?? UIImage(named:"head")!)
                    .resizable()
                    .renderingMode(.original)
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 120, height: 180)
                    .padding([.leading], 10.0)
                Spacer()
            }
            VStack(alignment: .leading) {
                Spacer()
                HStack {
                    Text( passport!.documentType)
                    Spacer()
                    Text( passport!.issuingAuthority)
                    Spacer()
                    Text( passport!.documentNumber)
                }
                Text( passport!.lastName)
                Text( passport!.firstName)
                Text( passport!.nationality)
                Text( passport!.dateOfBirth)
                Text( passport!.gender)
                Text( passport!.documentExpiryDate )
                
                Spacer()
            }.padding([.trailing], 10.0)
        }.frame(minWidth: 0, maxWidth: .infinity, minHeight: 0, maxHeight: .infinity, alignment: Alignment.topLeading)
            
    }
}

 
#if DEBUG
struct PassportView_Previews : PreviewProvider {
    @ObservedObject static var pd = PassportDetails()
    static var previews: some View {
//        let pptData = "P<GBRTEST<<TEST<TEST<<<<<<<<<<<<<<<<<<<<<<<<1234567891GBR8001019M2106308<<<<<<<<<<<<<<04"
//        let passport = Passport( passportMRZData: pptData, image:UIImage(named: "head")!, signed: false, dataValid: false )        
        
        return Group {
            PassportView(passportDetails: pd)
//            PassportView(passportDetails: $pd)
                .environment( \.colorScheme, .light)
            PassportView(passportDetails: pd)
//            PassportView(passportDetails: $pd)
                .environment( \.colorScheme, .dark)

        }.frame(width: UIScreen.main.bounds.width-10, height: 220)
        .environmentObject(pd)
    }
}
#endif

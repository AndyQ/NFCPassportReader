//
//  DetailsView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 30/10/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import NFCPassportReader

struct Item : Identifiable {
    var id = UUID()
    var title : String
    var value : String
}


struct DetailsView : View {
    @Binding var passportDetails: PassportDetails
    
    private var sectionNames = ["Chip information", "Document signing certificate", "Country signing certificate", "Datagroup Hashes"]
    private var sections = [[Item]]()

    init(passportDetails: Binding<PassportDetails>) {
        self._passportDetails = passportDetails
        if let passport = passportDetails.wrappedValue.passport {
            
            let docSigningDetails = passport.documentSigningCertificate?.getItemsAsDict() ?? [:]
            let countrySigningDetails = passport.countrySigningCertificate?.getItemsAsDict() ?? [:]
            let titles : [String] = ["Serial number", "Signature algorithm", "Public key algorithm", "Certificate fingerprint", "Issuer", "Subject", "Valid from", "Valid to"]
            var dsc = [Item]()
            var csc = [Item]()

            for title in titles {
                let ci = CertificateItem(rawValue:title)!

                dsc.append( Item(title:title, value: docSigningDetails[ci] ?? "") )
                    
                csc.append( Item(title:title, value: countrySigningDetails[ci] ?? "") )
            }
            let chipInfo = [Item(title:"LDS Version", value: passport.LDSVersion),
            Item(title:"Data groups present", value: passport.dataGroupsPresent.joined(separator: ", "))]
            
            var dgHashes = [Item]()
            for id in DataGroupId.allCases {
                if let hash = passport.dataGroupHashes[id] {
                    dgHashes.append( Item(title:hash.id, value:hash.match ? "MATCHED" : "UNMATCHED"))
                    dgHashes.append( Item(title:"SOD Hash", value: hash.sodHash))
                    dgHashes.append( Item(title:"Computed Hash", value: hash.computedHash))
                }
            }
            
            sections.append(chipInfo)
            sections.append(dsc)
            sections.append(csc)
            sections.append(dgHashes)
        }
    }

    var body: some View {
        GeometryReader { geometry in
            return List {
                ForEach( 0 ..< self.sectionNames.count ) { i in
                    SectionGroup(sectionTitle: self.sectionNames[i], items: self.sections[i], itemWidth: (geometry.size.width / 2)-10)
                }
            }
        }
    }
}

struct SectionGroup : View {
    var sectionTitle : String
    var items : [Item]
    var itemWidth: CGFloat
    
    var body: some View {
        Section(header: Text(sectionTitle)) {
            ForEach(self.items) { item in
                ItemRow(title: item.title, value: item.value, width: self.itemWidth)
            }
        }
    }
}

struct ItemRow : View {
    var width: CGFloat
    var title : String
    var value : String
    
    init( title: String, value: String, width: CGFloat ) {
        self.title = title
        self.value = value
        self.width = width
    }
    
    var body: some View {
        HStack(alignment:.top, spacing:0) {
            Text(self.title).frame(width: width, height: .none, alignment: .leading)
            Divider()
            Text(self.value)
                .lineLimit(nil)
                .frame(width: width, height: .none, alignment: .leading)

        }

    }
}


struct DetailsView_Previews: PreviewProvider {
    @State static var pd = PassportDetails()

    static var previews: some View {
        let passport = NFCPassportModel()
        pd.passport = passport
        return DetailsView(passportDetails:$pd )
            .environment( \.colorScheme, .light)
    }
}



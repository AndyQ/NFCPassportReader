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
    @ObservedObject var passportDetails: PassportDetails
    
    private var sectionNames = ["Chip information", "Verification information", "Document signing certificate", "Country signing certificate", "Datagroup Hashes"]
    private var sections = [[Item]]()

    var body: some View {
        GeometryReader { geometry in
            return List {
                ForEach( 0 ..< self.sectionNames.count ) { i in
                    SectionGroup(sectionTitle: self.sectionNames[i], items: self.sections[i], itemWidth: (geometry.size.width / 2)-10)
                }
            }
        }
    }
    

    
    init(passportDetails: PassportDetails) {
        self.passportDetails = passportDetails
        if let passport = passportDetails.passport {

            sections.append(getChipInfoSection(passport))
            sections.append(getVerificationDetailsSection(passport))
            sections.append(getCertificateSigningCertDetails(certItems:passport.documentSigningCertificate?.getItemsAsDict()))
            sections.append(getCertificateSigningCertDetails(certItems:passport.countrySigningCertificate?.getItemsAsDict()))
            sections.append(getDataGroupHashesSection(passport))
        }
    }

    func getChipInfoSection(_ passport: NFCPassportModel) -> [Item] {
        // Build Chip info section
        let chipInfo = [Item(title:"LDS Version", value: passport.LDSVersion),
                        Item(title:"Data groups present", value: passport.dataGroupsPresent.joined(separator: ", ")),
                        Item(title:"Data groups read", value: passport.dataGroupsAvailable.map { $0.getName()}.joined(separator: ", "))]

        return chipInfo
    }
    
    func getVerificationDetailsSection(_ passport: NFCPassportModel) -> [Item] {
        // Build Verification Info section
        var aa : String = "Not supported"
        if passport.activeAuthenticationSupported {
            aa = passport.activeAuthenticationPassed ? "SUCCESS\nSignature verified" : "FAILED\nCould not verify signature"
        }

        let verificationDetails : [Item] = [
            Item(title: "Access Control", value: "BAC"),
            Item(title: "Active Authentication", value: aa),
            Item(title: "Document Signing Certificate", value: passport.documentSigningCertificateVerified ? "SUCCESS\nSOD Signature verified" : "FAILED\nCouldn't verify SOD signature"),
            Item(title: "Country signing Certificate", value: passport.passportCorrectlySigned ? "SUCCESS\nmatched to country signing certificate" : "FAILED\nCouldn't build trust chain"),
            Item(title: "Data group hashes", value: passport.passportDataNotTampered ? "SUCCESS\nAll hashes match" : "FAILED\nCouldn't match hashes" )
        ]

        return verificationDetails
    }
    
    func getCertificateSigningCertDetails( certItems : [CertificateItem : String]? ) -> [Item] {
        let titles : [String] = ["Serial number", "Signature algorithm", "Public key algorithm", "Certificate fingerprint", "Issuer", "Subject", "Valid from", "Valid to"]

        var items = [Item]()
        if certItems?.count ?? 0  == 0 {
            items.append( Item(title:"Certificate details", value: "NOT FOUND" ) )
        } else {
            for title in titles {
                let ci = CertificateItem(rawValue:title)!
                items.append( Item(title:title, value: certItems?[ci] ?? "") )
            }
        }
        return items
    }

    func getDataGroupHashesSection(_ passport: NFCPassportModel) -> [Item] {
        var dgHashes = [Item]()
        for id in DataGroupId.allCases {
            if let hash = passport.dataGroupHashes[id] {
                dgHashes.append( Item(title:hash.id, value:hash.match ? "MATCHED" : "UNMATCHED"))
                dgHashes.append( Item(title:"SOD Hash", value: hash.sodHash))
                dgHashes.append( Item(title:"Computed Hash", value: hash.computedHash))
            }
        }
        return dgHashes
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
    @ObservedObject static var pd = PassportDetails()

    static var previews: some View {
        let passport = NFCPassportModel()
        pd.passport = passport
        return DetailsView(passportDetails:pd )
            .environment( \.colorScheme, .light)
    }
}



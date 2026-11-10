//
//  MRZEntryView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 10/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import SwiftUI

// This will be removed once DatePicker inline works correctly
struct DateView : View {
    @Binding var date : Date
    var title : String

    var body : some View {
        VStack {
            Text(title)
                .font(.largeTitle)
            Spacer()
            DatePicker("Date of birth", selection:$date, displayedComponents: .date)
                .environment(\.timeZone, TimeZone(secondsFromGMT: 0)!)
                .datePickerStyle(WheelDatePickerStyle())
                .labelsHidden()
            Spacer()
        }
    }
}

// This should be a nice simple inline DatePicker here
// BUT there are bugs when you select dates it changes the date format
// from DD MMM YYYY to DD/MM/YYYY!)
// Will update when/if this gets fixed!
struct MRZEntryView : View {
    @EnvironmentObject var settings: SettingsStore
    
    // These will be removed once DatePicker inline works correctly
    @State private var editDOB = false
    @State private var editDOE = false
    @State private var editDateTitle : String = ""

    var body : some View {
        let passportNrBinding = Binding<String>(get: {
            settings.passportNumber
        }, set: {
            settings.passportNumber = $0.uppercased()
        })
        VStack {
            NavigationLink( destination: DateView(date:$settings.dateOfBirth, title:editDateTitle), isActive: $editDOB) { Text("") }
            NavigationLink( destination: DateView(date:$settings.dateOfExpiry, title:editDateTitle), isActive: $editDOE) { Text("") }

            TextField("Passport number", text: passportNrBinding)
                .textCase(.uppercase)
                .modifier(ClearButton(text: passportNrBinding))
                .textContentType(.name)
                .foregroundColor(Color.primary)
                .padding([.leading, .trailing])
                .ignoresSafeArea(.keyboard, edges: .all)

            Divider()

            // Replace with DatePicker once it works correctly
            HStack {
                VStack {
                    Text( "Date of birth" )
                    Button(formatDate(settings.dateOfBirth)) {
                        editDateTitle = "Select date of birth"
                        editDOB = true
                    }
                    .padding(.horizontal, 15)
                    .padding(.vertical, 8)
                    .background(Color.black.opacity(0.07))
                    .cornerRadius(8)
                }
                Spacer()
                VStack {
                    Text( "Passport expiry date" )
                    Button(formatDate(settings.dateOfExpiry)) {
                        editDateTitle = "Select passport expiry date"
                        editDOE = true
                    }
                    .padding(.horizontal, 15)
                    .padding(.vertical, 8)
                    .background(Color.black.opacity(0.07))
                    .cornerRadius(8)
                }
            }
                .padding([.leading, .trailing])

            Divider()
        }
        .ignoresSafeArea(.keyboard, edges: .bottom)
    }
}

/// Entry for the Card Access Number: 6 digits printed on the data page, used with PACE instead of the MRZ.
struct CANEntryView : View {
    @EnvironmentObject var settings: SettingsStore

    var body : some View {
        let canBinding = Binding<String>(get: {
            settings.can
        }, set: {
            settings.can = String($0.filter(\.isNumber).prefix(6))
        })
        VStack(alignment: .leading) {
            TextField("Card Access Number (CAN)", text: canBinding)
                .keyboardType(.numberPad)
                .modifier(ClearButton(text: canBinding))
                .foregroundColor(Color.primary)
                .padding([.leading, .trailing, .top])
            Divider()
            Text("The 6-digit CAN printed on the document's data page. It only works with PACE, so documents without PACE (or that don't accept the CAN) can't be read with it.")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding([.leading, .trailing])
        }
        .ignoresSafeArea(.keyboard, edges: .bottom)
    }
}

// This will be removed once DatePicker inline works correctly
extension MRZEntryView {
    
    func formatDate( _ date : Date ) -> String {
        let df = DateFormatter()
        df.timeZone = TimeZone.init(secondsFromGMT: 0)
        df.dateFormat = "dd MMM yyyy"
        let dateStr = df.string(from:date)
        return dateStr
    }
}

#if DEBUG
struct MRZEntryView_Previews : PreviewProvider {
    
    static var previews: some View {
        let settings = SettingsStore()
        
        return
            Group {
                NavigationView {
                    MRZEntryView()
                }
                .environmentObject(settings)
                .environment( \.colorScheme, .light)
        }
    }
}
#endif


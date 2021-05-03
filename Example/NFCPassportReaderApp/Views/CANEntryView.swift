//
//  CANEntryView.swift
//  NFCPassportReaderApp
//
//  Created by Tim Wilbrink on 23.04.21.
//

import SwiftUI

struct CANEntryView : View {
    @EnvironmentObject var settings: SettingsStore

    // These will be removed once DatePicker inline works correctly
    @State private var editDOB = false
    @State private var editDOE = false
    @State private var editDateTitle : String = ""

    var body : some View {
        let canBinding = Binding<String>(get: {
            settings.cardAccessNumber
        }, set: {
            settings.cardAccessNumber = $0.uppercased()
        })
        VStack {

            TextField("CAN", text: canBinding)
                .textCase(.uppercase)
                .modifier(ClearButton(text: canBinding))
                .textContentType(.name)
                .foregroundColor(Color.primary)
                .padding([.leading, .trailing])
                .ignoresSafeArea(.keyboard, edges: .all)

            Divider()


        }
        .ignoresSafeArea(.keyboard, edges: .bottom)
    }
}


#if DEBUG
struct CANEntryView_Previews : PreviewProvider {

    static var previews: some View {
        let settings = SettingsStore()

        return
            Group {
                NavigationView {
                    CANEntryView()
                }
                .environmentObject(settings)
                .environment( \.colorScheme, .light)
        }
    }
}
#endif

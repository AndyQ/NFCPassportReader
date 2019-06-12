//
//  ContentView.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI

struct ContentView : View {
    @State var passportNumber: String = ""
    @State var dateOfBirth: String = ""
    @State var expiryDate: String = ""
    var body: some View {
        
        VStack {
            Text("Include checksums on below fields")
            TextField($passportNumber)
            TextField($dateOfBirth)
            TextField($expiryDate)

            Button(action: {
                // your action here
            }) {
                Text("Scan Passport")
            }

        }

    }
}

#if DEBUG
struct ContentView_Previews : PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
#endif

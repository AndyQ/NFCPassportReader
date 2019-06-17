//
//  DetailView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 16/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI

struct DetailView : View {
    @Binding
    var shouldDismiss : Bool
    
    var mrzData : String
    var image : UIImage?

    @Environment(\.isPresented) private var isPresented

    var body: some View {
        VStack( alignment: .leading) {
            
            Button(action: {
                self.shouldDismiss.toggle()
            }) {
                Text("Close")
            }.font(.title)
                .foregroundColor(Color.secondary)
                .padding()

            Image(uiImage: image ?? UIImage())
                .padding()
            Text(mrzData)
                .lineLimit(0)
            Spacer()
        }
    }
    
}

/*
#if DEBUG
struct DetailView_Previews : PreviewProvider {
    static var previews: some View {
        var dismiss = false
        DetailView( mrzData: "", image:nil, dismissFlag: dismiss)
    }
}
#endif
 */

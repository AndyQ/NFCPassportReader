//
//  ViewExt.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 11/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import SwiftUI

#if canImport(UIKit)
extension View {
    func hideKeyboard() {
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    }
}
#endif

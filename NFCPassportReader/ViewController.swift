//
//  ViewController.swift
//  NFCTest
//
//  Created by Andy Qua on 06/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import CoreNFC
import CryptoKit



class ViewController: UIViewController {
    
    @IBOutlet weak var passportNrText: UITextField!
    @IBOutlet weak var dateOfBirthText: UITextField!
    @IBOutlet weak var passportExpiryText: UITextField!

//    var readerSession: NFCTagReaderSession?
            
    var passportReader = PassportReader()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Set log level

        let d = UserDefaults.standard
        
        self.passportNrText.text = d.string(forKey: "passportNumber") ?? ""
        self.dateOfBirthText.text = d.string(forKey: "dateOfBirth") ?? ""
        self.passportExpiryText.text = d.string(forKey: "expiryDate") ?? ""

    }
    
    override func touchesBegan(_ touches: Set<UITouch>,
                               with event: UIEvent?) {
        self.view.endEditing(true)
    }

    
    // MARK: - Actions
    @IBAction func scanTag(_ sender: Any) {
        self.view.endEditing(true)

        guard let passportNr = self.passportNrText.text, passportNr.count > 8,
            let dateOfBirth = self.dateOfBirthText.text, dateOfBirth.count == 6,
            let expiryDate = self.passportExpiryText.text, expiryDate.count == 6 else {
                
                let alertController = UIAlertController( title: "Invalid Passport details", message:"The passport details specified are invalid. Please check", preferredStyle: .alert)
                alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                self.present(alertController, animated: true, completion: nil)

                return
        }

        // Store last entered details
        let d = UserDefaults.standard
        d.set(passportNr, forKey: "passportNumber")
        d.set(dateOfBirth, forKey: "dateOfBirth")
        d.set(expiryDate, forKey: "expiryDate")
        
        // Calculate checksums
        let passportNrChksum = calcCheckSum(self.passportNrText.text!)
        let dateOfBirthChksum = calcCheckSum(self.dateOfBirthText.text!)
        let expiryDateChksum = calcCheckSum(self.passportExpiryText.text!)

        let mrzKey = "\(passportNr)\(passportNrChksum)\(dateOfBirth)\(dateOfBirthChksum)\(expiryDate)\(expiryDateChksum)"
        
        passportReader.readPassport(mrzKey: mrzKey, completed: { (error) in
            if let error = error {
                var title : String
                var message : String
                if error == .NFCNotSupported {
                    title = "Scanning Not Supported"
                    message = "This device doesn't support tag scanning."
                } else {
                    title = "Problem reading passport"
                    message = "\(error)"
                }
                
                DispatchQueue.main.async {
                    let alertController = UIAlertController( title: title, message:message, preferredStyle: .alert)
                    alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
                    self.present(alertController, animated: true, completion: nil)
                }


            } else {
                DispatchQueue.main.async {
                    self.performSegue(withIdentifier: "ShowPassport", sender: self)
                }

            }
        })
    }
    
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
    
    @IBSegueAction func prepareDetailsView(_ coder: NSCoder) -> DetailViewController? {
        return DetailViewController(coder: coder, mrz:passportReader.passportMRZ, image:passportReader.passportImage)
    }
}

extension ViewController : UITextFieldDelegate {
    func textFieldDidBeginEditing(_ textField: UITextField) {
        textField.text = ""
    }

}

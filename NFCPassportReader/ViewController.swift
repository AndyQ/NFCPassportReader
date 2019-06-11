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

    var readerSession: NFCTagReaderSession?
            
    var passportReader : PassportReader?

    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Set log level
        log.logLevel = .warning

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

        // Store last entered details
        let d = UserDefaults.standard
        d.set(self.passportNrText.text, forKey: "passportNumber")
        d.set(self.dateOfBirthText.text, forKey: "dateOfBirth")
        d.set(self.passportExpiryText.text, forKey: "expiryDate")
        
        guard NFCNDEFReaderSession.readingAvailable else {
            let alertController = UIAlertController(
                title: "Scanning Not Supported",
                message: "This device doesn't support tag scanning.",
                preferredStyle: .alert
            )
            alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alertController, animated: true, completion: nil)
            return
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            readerSession?.alertMessage = "Hold your iPhone near an NFC enabled passport."
            readerSession?.begin()
        }
    }
    
    
    @IBSegueAction func prepareDetailsView(_ coder: NSCoder) -> DetailViewController? {
        return DetailViewController(coder: coder, mrz:passportReader?.passportMRZ, image:passportReader?.passportImage)
    }
}

extension ViewController : UITextFieldDelegate {
    func textFieldDidBeginEditing(_ textField: UITextField) {
        textField.text = ""
    }

}

extension ViewController : NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        log.debug( "tagReaderSessionDidBecomeActive" )
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        log.debug( "tagReaderSession:didInvalidateWithError - \(error)" )
        self.readerSession = nil
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        log.debug( "tagReaderSession:didDetect - \(tags[0])" )
        if tags.count > 1 {
            session.alertMessage = "More than 1 tags was found. Please present only 1 tag."
            return
        }
        
        let tag = tags.first!
        var ppttag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            ppttag = tag
        default:
            session.invalidate(errorMessage: "Tag not valid.")
            return
        }

        // Connect to tag
        session.connect(to: tag) { [unowned self] (error: Error?) in
            if error != nil {
                session.invalidate(errorMessage: "Connection error. Please try again.")
                return
            }
            
            self.readerSession?.alertMessage = "Authenticating with passport....."

            var mrzKey : String = ""
            DispatchQueue.main.sync {
                mrzKey = self.passportNrText.text! + self.dateOfBirthText.text! + self.passportExpiryText.text!
            }

            self.passportReader = PassportReader( passportTag:ppttag )
            self.passportReader?.sendUpdateMessage = { [unowned self] msg in
                self.readerSession?.alertMessage = msg
            }
            
            self.passportReader?.readPassport(mrzKey: mrzKey, completed: { (error) in
                if error == nil {
                    session.invalidate()
                    DispatchQueue.main.async {
                        self.performSegue(withIdentifier: "ShowPassport", sender: self)
                    }
                } else {
                    session.invalidate(errorMessage: "Sorry, there was a problem reading the passport. Please try again" )

                }

            })
        }
    }
}


//
//  DetailViewController.swift
//  NFCTest
//
//  Created by Andy Qua on 10/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import NFCPassportReader

class DetailViewController: UIViewController {

    @IBOutlet weak var imageView: UIImageView!
    @IBOutlet weak var mrzLabel: UILabel!
    @IBOutlet weak var validationStatus: UILabel!

    var passport : Passport?

    required init?(coder : NSCoder, passport: Passport? ) {
        super.init(coder:coder)

        self.passport = passport
    }
    
    required init?(coder: NSCoder) {
        super.init(coder:coder)
    }
    
    
    override func viewDidLoad() {
        super.viewDidLoad()

        if let passport = passport {
            self.mrzLabel.text = passport.passportMRZ
            self.imageView.image = passport.passportImage
        }
        
        self.validationStatus.text = "Validation Status: NOT Validated"
    }
    
    @IBAction func closePressed(_ sender: Any) {
        self.dismiss(animated: true, completion: nil)
    }
    
    @IBAction func validatePressed(_ sender: Any) {
        guard let sod = passport?.getDataGroup(.SOD) else { return }
        
        guard let dg1 = passport?.getDataGroup(.DG1),
            let dg2 = passport?.getDataGroup(.DG2) else { return }
        
        let pa =  PassiveAuthentication()
        
        do {
            try pa.validatePassport( sodBody : sod.body, dataGroupsToCheck: [.DG1:dg1, .DG2:dg2] )
                self.validationStatus.text = "Validation Status: Validated"
                self.validationStatus.textColor = .green
        } catch let error as PassiveAuthenticationError {
            self.validationStatus.text = "Validation Status: Invalid - \(error.localizedDescription)"
            self.validationStatus.textColor = .red
            switch error {
            case PassiveAuthenticationError.InvalidDataGroupHash(let msg):
                Log.error( error.localizedDescription )
                Log.error( msg )
            default:
                Log.error( error.localizedDescription )
            }
        } catch {
            Log.error( "Unexpected error - \(error)" )
        }
    }
}

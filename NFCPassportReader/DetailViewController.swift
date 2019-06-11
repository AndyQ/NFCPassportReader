//
//  DetailViewController.swift
//  NFCTest
//
//  Created by Andy Qua on 10/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit

class DetailViewController: UIViewController {

    @IBOutlet weak var imageView: UIImageView!
    @IBOutlet weak var mrzLabel: UILabel!
    
    var mrz : String?
    var image : UIImage?

    required init?(coder : NSCoder, mrz: String?, image: UIImage? ) {
        super.init(coder:coder)

        self.mrz = mrz
        self.image = image
    }
    
    required init?(coder: NSCoder) {
        super.init(coder:coder)
    }
    
    
    override func viewDidLoad() {
        super.viewDidLoad()

        if let mrz = mrz {
            self.mrzLabel.text = mrz
        }
        self.imageView.image = image
    }
    
    @IBAction func closePressed(_ sender: Any) {
        self.dismiss(animated: true, completion: nil)
    }
}

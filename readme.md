# NFCPassportReader

This package handles reading an NFC Enabled passport using iOS 13 CoreNFC APIS

THIS IS AN IN-PROGRESS BRANCH AND NOT EVEN REMOTELY SUPPORTED! IT MAY CRASH OR JUST NOT WORK!


Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads DG1 (MRZ data) and DG2 (Image) in both JPEG and JPEG2000 formats, DG7, DG11, DG12, DG14 and DG15 (also SOD and COM datagroups)
* Passive Authentication
* Active Authentication
* Chip Authentication (ECDH DES and AES keys tested, DH DES AES keys implemented ad should work but currently not tested)
* PACE - currently only Generic Mapping (GM) supported
* Ability to dump passport stream and read it back in

This is still very early days - the code is by no means perfect and there are still some rough edges  - there ARE most definitely bugs and I'm sure I'm not doing things perfectly. 

It reads and verifies my passport (and others I've been able to test) fine, however your mileage may vary.

## Installation
### Swift Package Manager

NFCPassportReader may be installed via Swift Package Manager, by pointing to this repo's URL.


### CocoaPods

Install using [CocoaPods](http://cocoapods.org) by adding this line to your Podfile:

```ruby
use_frameworks!
pod 'NFCPassportReader', git:'https://github.com/AndyQ/NFCPassportReader.git'  
```

Then, run the following command:

```bash
$ pod install
```

Note - Current Bitcode is disabled as OpenSSL is not correctly found.  Hopefully this will be fixed in a future release.

## Usage 
To use, you first need to create the Passport MRZ Key which consists of the passport number, date of birth and expiry date (including the checksums).
Dates are in YYMMDD format

For example:

```
<passport number><passport number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>

e.g. for Passport nr 12345678, Date of birth 27-Jan-1998, Expiry 30-Aug-2025 the MRZ Key would be:

Passport number - 12345678
Passport number checksum - 8
Date Of birth - 980127
Date of birth checksum - 7
Expiry date - 250831
Expiry date checksum - 5

mrzKey = "12345678898012772508315"
```

Then on an instance of PassportReader, call the readPassport method passing in the mrzKey, the datagroups to read and a completion block.  
e.g.

```
passportReader.readPassport(mrzKey: mrzKey, tags: [.COM, .DG1, .DG2], completed: { (error) in
   ...
}
```

Currently the datagroups supported are: COM, DG1, DG2, DG7, DG11, DG12, DG14 (partial), DG15, and SOD

This will then handle the reading of the passport, and image and will call the completion block either with an TagError error if there was an error of some kind, or nil if successful.

If successful, the passportReader object will then contain valid data for the passportMRZ and passportImage fields.

In addition, you can customise the messages displayed in the NFC Session Reader by providing a customDisplayMessage callback
e.g. to override just the initial request to present passport message:

```
passportReader.readPassport(mrzKey: mrzKey, tags: [.COM, .DG1, .DG2],
    customDisplayMessage: { (displayMessage) in
        switch displayMessage {
            case .requestPresentPassport:
                return "Hold your iPhone near an NFC enabled passport."
            default: 
                return nil
    }, completed: { (error) in
        ...
}
```


## Logging
Additional logging (very verbose)  can be enabled on the PassportReader by passing in a log level on creation:
e.g.

```
let reader = PassportReader(logLevel: .debug)
```

NOTE - currently this is just printing out to the console - I'd like to implement better logging later - probably using SwiftyBeaver 

### PassiveAuthentication
Passive Authentication is now part of the main library and can be used to ensure that an E-Passport is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list (either from a country that publishes their master list, or the ICAO PKD repository). See the scripts folder for details on how to get and create this file.

**The masterList.pem file included in the Sample app is purely there to ensure no compiler warnings and contains only a single PEM file that was self-generated and won't be able to verify anything!**

## Sample app
There is a sample app included in the repo which demonstrates the functionality.


## Troubleshooting
* If when doing the initial Mutual Authenticate challenge, you get an error with and SW1 code 0x63, SW2 code 0x00, reason: No information given, then this is usualy because your MRZ key is incorrect, and possibly because your passport number is not quite right.  If your passport number in the MRZ contains a '<' then you need to include this in the MRZKey - the checksum should work out correct too.  For more details, check out App-D2 in the ICAO 9303 Part 11 document (https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
<br><br>e.g. if the bottom line on the MRZ looks like:
12345678<8AUT7005233M2507237<<<<<<<<<<<<<<06
<br><br>
In this case the passport number is 12345678 but is padded out with an additonal <. This needs to be included in the MRZ key used for BAC.
e.g. 12345678<870052332507237 would be the key used.



## To do
There are a number of things I'd like to implement in no particular order:
 * Finish off PACE authentication (IM and CAM)
 

## Thanks
I'd like to thank the writers of pypassport (Jean-Francois Houzard and Olivier Roger - can't find their website but referenced from https://github.com/andrew867/epassportviewer) who's work this is based on.

The EPassport section on YobiWiki (http://wiki.yobi.be/wiki/EPassport)  This has been an invaluable resource especially around Passive Authentication.

Marcin Krzyżanowski for his OpenSSL-Universal repo.


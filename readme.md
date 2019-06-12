# NFCPassportReader

This package handles reading an NFC Enabled passport using iOS 13 CoreNFC APIS


Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads DG1 (MRZ data) and DG2 (Image) in both JPEG and JPEG2000 formats

This is still very early days - the code is by no means perfect and there are still some rough edges  - there ARE most definately bugs and I'm sure I'm not doing things perfectly. 

It reads my passport (and others I've been able to test) fine, however your milage may vary.

## Usage 
To use, you first need to create the Passport MRZ Key which consists of the passport number, date of birth and expiry date (including the checksums).
`
E.g. <passport number><passport number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>
`

Then on an instance of PassportReader, call the readPassport method passing in the mrzKey, and a completion block.  
e.g.
`passportReader.readPassport(mrzKey: mrzKey, completed: { (error) in
...
}
`
This will then handle the reading of the passport, and image and will call the completion block either with an TagError error if there was an error of some kind, or nil if successful.

If successful, the passportReader object will then contain valid data for the passportMRZ and passportImage fields.

## Logging
Additional logging (very verbose)  can be enabled on the PassportReader by passing in a log level on creation:
e.g.
`let reader = PassportReader(logLevel: .debug)
`

NOTE - currently this is just printing out to the console - I'd like to implement better logging later - probably using SwiftyBeaver 

## Sample
There is a sample app included in the repo which demonstrates the functionality.

## To do
There are a number of things I'd like to implement in no particular order:
 * Proper parsing of DG1 datagroup (MRZ data)
 * Ability to select which datagroups are read - currently both DG1 and DG2 are read
 * Ability to dump passport stream and read it back in
 

## Thanks
I'd like to thank the writers of pypassport (Jean-Francois Houzard and Olivier Roger - can't find their website but referenced from https://github.com/andrew867/epassportviewer) who's work this is based on.

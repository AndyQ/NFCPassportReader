//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//


int retrievePKCS7Certificate( const char *infile, const char *outfile, int inFormat, int printCerts, int isText);
int verifyX509Certificate(const char *certif, const char *trustedCertif);
int getPkcs7SignatureContent(int verify, const char *inFile, const char *outFile, int inFormat, int noVerify );
int asn1parse( const char *inFile, const char *outFile, int inFormat, int indent );

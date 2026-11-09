import XCTest
@testable import NFCPassportReader

#if !os(macOS)
@available(iOS 15, *)
final class BACHandlerTests: XCTestCase {

    func testSessionKeysAcceptsValidMutualAuthResponse() throws {
        let bac = makeBACReadyForSessionKeys()
        let (eicc, micc, _) = buildMutualAuthResponse(bac: bac)
        XCTAssertNoThrow(try bac.sessionKeys(data: eicc + micc))
    }

    func testSessionKeysRejectsBadMAC() throws {
        let bac = makeBACReadyForSessionKeys()
        var (eicc, micc, _) = buildMutualAuthResponse(bac: bac)
        micc[7] ^= 0xFF
        XCTAssertThrowsError(try bac.sessionKeys(data: eicc + micc)) { error in
            guard case NFCPassportReaderError.InvalidResponseChecksum = error else {
                XCTFail("expected InvalidResponseChecksum, got \(error)")
                return
            }
        }
    }

    func testSessionKeysRejectsWrongRNDIFD() throws {
        let bac = makeBACReadyForSessionKeys()
        var wrongIfd = bac.rnd_ifd
        wrongIfd[0] ^= 0x01
        let kicc = [UInt8](repeating: 0xB2, count: 16)
        let plaintext = bac.rnd_icc + wrongIfd + kicc
        let eicc = tripleDESEncrypt(key: bac.ksenc, message: plaintext, iv: [UInt8](repeating: 0, count: 8))
        let micc = mac(algoName: .DES, key: bac.ksmac, msg: pad(eicc, blockSize: 8))
        XCTAssertThrowsError(try bac.sessionKeys(data: eicc + micc))
    }

    func testSessionKeysRejectsShortResponse() throws {
        let bac = makeBACReadyForSessionKeys()
        XCTAssertThrowsError(try bac.sessionKeys(data: [UInt8](repeating: 0, count: 32)))
    }

    private func makeBACReadyForSessionKeys() -> BACHandler {
        let bac = BACHandler()
        bac.ksenc = hexRepToBin("00112233445566778899AABBCCDDEEFF")
        bac.ksmac = hexRepToBin("FFEEDDCCBBAA99887766554433221100")
        _ = bac.authentication(rnd_icc: [UInt8](repeating: 0xA1, count: 8))
        return bac
    }

    private func buildMutualAuthResponse(bac: BACHandler) -> ([UInt8], [UInt8], [UInt8]) {
        let kicc = [UInt8](repeating: 0xB2, count: 16)
        let plaintext = bac.rnd_icc + bac.rnd_ifd + kicc
        let eicc = tripleDESEncrypt(key: bac.ksenc, message: plaintext, iv: [UInt8](repeating: 0, count: 8))
        let micc = mac(algoName: .DES, key: bac.ksmac, msg: pad(eicc, blockSize: 8))
        return (eicc, micc, kicc)
    }
}
#endif

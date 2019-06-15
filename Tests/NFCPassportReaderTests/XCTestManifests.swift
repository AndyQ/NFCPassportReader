import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(NFCPassportReaderTests.allTests),
        testCase(DataGroupParsingTests.allTests),
    ]
}
#endif

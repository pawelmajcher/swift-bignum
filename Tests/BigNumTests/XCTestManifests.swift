import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    let testCase = BigNumTests()

    return [
        testCase([
            ("testConversion", testCase.testConversion),
            ("testBasic", testCase.testBasic),
            ("testAdd", testCase.testAdd),
            ("testSubtract", testCase.testSubtract),
            ("testMultiple", testCase.testMultiple),
            ("testDivide", testCase.testDivide),
            ("testModulus", testCase.testModulus),
            ("testSquare", testCase.testSquare),
            ("testPower", testCase.testPower),
            ("testModAdd", testCase.testModAdd),
            ("testModSubtract", testCase.testModSubtract),
            ("testModMultiple", testCase.testModMultiple),
            ("testModSquare", testCase.testModSquare),
            ("testModPower", testCase.testModPower),
            ("testLargeModPower", testCase.testLargeModPower),
            ("testGCD", testCase.testGCD),
            ("testLeftShift", testCase.testLeftShift),
            ("testRightShift", testCase.testRightShift),
            ("testNotHex", testCase.testNotHex),
            ("testRandom", testCase.testRandom),
            ("testPrime", testCase.testPrime),
            ("testFactorial", testCase.testFactorial)
        ]),
    ]
}
#endif

// swift-tools-version:5.4
import PackageDescription

let package = Package(
  name: "NFCPassportReader",
  platforms: [.iOS("15.0")],
  products: [
    .library(
      name: "NFCPassportReader",
      targets: ["NFCPassportReader"])
  ],
  dependencies: [
    .package(
      url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.6.0001"))
  ],
  targets: [
    // Targets are the basic building blocks of a package. A target can define a module or a test suite.
    // Targets can depend on other targets in this package, and on products in packages which this package depends on.
    .target(
      name: "NFCPassportReader",
      dependencies: [
        .product(name: "OpenSSL", package: "OpenSSL-Package")
      ]),
    .testTarget(
      name: "NFCPassportReaderTests",
      dependencies: [
        "NFCPassportReader",
        .product(name: "OpenSSL", package: "OpenSSL-Package"),
      ]),
  ]
)

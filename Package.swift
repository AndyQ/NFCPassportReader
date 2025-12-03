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

Pod::Spec.new do |spec|

  spec.name         = "NFCPassportReader"
  spec.version      = "2.3.0"
  spec.summary      = "This package handles reading an NFC Enabled passport using iOS 13 CoreNFC APIS"

  spec.homepage     = "https://github.com/AndyQ/NFCPassportReader"
  spec.license      = "MIT"
  spec.author       = { "Andy Qua" => "andy.qua@gmail.com" }
  spec.platform = :ios
  spec.ios.deployment_target = "15.0"

  spec.source       = { :git => "https://github.com/AndyQ/NFCPassportReader.git", :tag => "#{spec.version}" }

  spec.source_files  = "Sources/**/*.{swift}"

  spec.swift_version = "5.4"

  spec.dependency "OpenSSL-Universal", '3.3.3001'
  spec.xcconfig          = { 'OTHER_LDFLAGS' => '-weak_framework CryptoKit -weak_framework CoreNFC -weak_framework CryptoTokenKit' }

end

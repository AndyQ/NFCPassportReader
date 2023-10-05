//
//  FaceImageInfo.swift
//  NFCPassportReader
//
//  Created by Terje Lønøy on 22/05/2023.
//  Copyright © 2023 Andy Qua. All rights reserved.
//

import Foundation

/**
 Data structure for storing facial image data. This represents
 a facial record data block as specified in Section 5.5, 5.6,
 and 5.7 of ISO/IEC FCD 19794-5 (2004-03-22, AKA Annex D).

 Integration based on [JMRTD](https://sourceforge.net/p/jmrtd/code/HEAD/tree/trunk/jmrtd/src/main/java/org/jmrtd/lds/iso19794/FaceImageInfo.java#l59)
 */
public struct FaceImageInfo: Equatable {
    let expression: Expression?
    let eyeColor: EyeColor?
    let faceImageType: FaceImageType?
    let features: Features?
    let hairColor: HairColor?
    let imageColorSpace: ImageColorSpace?
    let imageDataType: ImageDataType?
    let sourceType: SourceType?
    
    internal static func from(dg2: DataGroup2) -> FaceImageInfo {
        return FaceImageInfo(
            expression: Expression.from(dg2.expression),
            eyeColor: EyeColor.from(dg2.eyeColor),
            faceImageType: FaceImageType.from(dg2.faceImageType),
            features: Features.from(dg2.featureMask),
            hairColor: HairColor.from(dg2.hairColor),
            imageColorSpace: ImageColorSpace.from(dg2.imageColorSpace),
            imageDataType: ImageDataType.from(dg2.imageDataType),
            sourceType: SourceType.from(dg2.sourceType)
        )
    }
    
    /// Expression code based on Section 5.5.7 of ISO 19794-5.
    public enum Expression: Int {
        case unspecified = 0x0000
        case neutral = 0x0001
        case smileClosed = 0x0002
        case smileOpen = 0x0003
        case raisedEyebrows = 0x0004
        case eyesLookingAway = 0x0005
        case squinting = 0x0006
        case frowning = 0x0007
        
        public static func from(_ code: Int) -> Expression? {
            return Expression(rawValue: code)
        }
    }

    /// Eye color code based on Section 5.5.4 of ISO 19794-5.
    public enum EyeColor: Int {
        case unspecified = 0x00
        case black = 0x01
        case blue = 0x02
        case brown = 0x03
        case gray = 0x04
        case green = 0x05
        case multiColored = 0x06
        case pink = 0x07
        case unknown = 0xFF
        
        public static func from(_ code: Int) -> EyeColor? {
            return EyeColor(rawValue: code)
        }
    }
    
    /// Face image type code based on Section 5.7.1 of ISO 19794-5.
    public enum FaceImageType: Int {
        case basic = 0x00
        case fullFrontal = 0x01
        case tokenFrontal = 0x02
        
        public static func from(_ code: Int) -> FaceImageType? {
            return FaceImageType(rawValue: code)
        }
    }
    
    /// Feature flags meaning based on Section 5.5.6 of ISO 19794-5.
    public enum Features: Int {
        case featuresAreSpecified = 0x000001
        case glasses = 0x000002
        case moustache = 0x000004
        case beard = 0x000008
        case teethVisible = 0x000010
        case blink = 0x000020
        case mouthOpen = 0x000040
        case leftEyePatch = 0x000080
        case rightEyePath = 0x000100
        case darkGlasses = 0x000200
        case distortingMedicalCondition = 0x000400
        
        public static func from(_ code: Int) -> Features? {
            return Features(rawValue: code)
        }
    }
    
    /// Hair color code based on Section 5.5.5 of ISO 19794-5.
    public enum HairColor: Int {
        case unspecified = 0x00
        case bald = 0x01
        case black = 0x02
        case blonde = 0x03
        case brown = 0x04
        case gray = 0x05
        case white = 0x06
        case red = 0x07
        case green = 0x08
        case blue = 0x09
        case unknown = 0xFF
        
        public static func from(_ code: Int) -> HairColor? {
            return HairColor(rawValue: code)
        }
    }
    
    /// Color space code based on Section 5.7.4 of ISO 19794-5.
    public enum ImageColorSpace: Int {
        case unspecified = 0x00
        case rgb24 = 0x01
        case yuv422 = 0x02
        case gray8 = 0x03
        case other = 0x04
        
        public static func from(_ code: Int) -> ImageColorSpace? {
            return ImageColorSpace(rawValue: code)
        }
    }
    
    /// Image data type code based on Section 5.7.2 of ISO 19794-5.
    public enum ImageDataType: Int {
        case jpeg = 0x00
        case jpeg2000 = 0x01
        
        public static func from(_ code: Int) -> ImageDataType? {
            return ImageDataType(rawValue: code)
        }
    }
    
    /// Source type based on Section 5.7.6 of ISO 19794-5.
    public enum SourceType: Int {
        case unspecified = 0x00
        case staticPhotoUnknownSource = 0x01
        case staticPhotoDigitalCam = 0x02
        case staticPhotoScanner = 0x03
        case videoFrameUnknownSource = 0x04
        case videoFrameAnalogCam = 0x05
        case videoFrameDigitalCam = 0x06
        case unknown = 0x07
        
        public static func from(_ code: Int) -> SourceType? {
            return SourceType(rawValue: code)
        }
    }
}

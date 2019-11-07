//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

// TODO: Quick log functions - will move this to something better
public enum LogLevel : Int {
    case verbose = 0
    case debug = 1
    case info = 2
    case warning = 3
    case error = 4
}

public class Log {
    public static var logLevel : LogLevel = .info

    public class func verbose( _ msg : String ) {
        log( .verbose, msg )
    }
    public class func debug( _ msg : String ) {
        log( .debug, msg )
    }
    public class func info( _ msg : String ) {
        log( .info, msg )
    }
    public class func warning( _ msg : String ) {
        log( .warning, msg )
    }
    public class func error( _ msg : String ) {
        log( .error, msg )
    }
    
    class func log( _ logLevel : LogLevel, _ msg : String ) {
        if self.logLevel.rawValue <= logLevel.rawValue {
            print( msg )
        }
    }
}

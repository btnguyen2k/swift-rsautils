//
//  RSAUtils.swift
//  Swift-RSAUtils
//
//  Created by Thanh Nguyen on 7/10/15.
//  Copyright (c) 2015 Thanh Nguyen. All rights reserved.
//
////////////////////////////////////////////////////////////////////////
// RSA Utility Class
// Credits:
// - https://github.com/ideawu/Objective-C-RSA
// - http://netsplit.com/swift-storing-key-pairs-in-the-keyring
// - http://netsplit.com/swift-generating-keys-and-encrypting-and-decrypting-text

import Foundation
import Security

public class RSAUtils: NSObject {
    // Base64 encode a block of data
    static private func base64Encode(data: NSData) -> String {
        return data.base64EncodedStringWithOptions(nil)
    }
    
    // Base64 decode a base64-ed string
    static private func base64Decode(strBase64: String) -> NSData {
        let data = NSData(base64EncodedString: strBase64, options: nil)
        return data!
    }
    
    // Verify that the supplied key is in fact a PKCS#1 key and strip the header
    static public func stripPublicKeyHeader(pubkey: NSData) -> NSData? {
        if ( pubkey.length == 0 ) {
            return nil
        }
        
        var keyAsArray = [UInt8](count: pubkey.length / sizeof(UInt8), repeatedValue: 0)
        pubkey.getBytes(&keyAsArray, length: pubkey.length)
        
        var idx = 0
        if (keyAsArray[idx++] != 0x30) {
            return nil
        }
        if (keyAsArray[idx] > 0x80) {
            idx += Int(keyAsArray[idx]) - 0x80 + 1
        } else {
            idx++
        }
        
        let seqiod = [UInt8](arrayLiteral: 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00)
        for ( var i = idx; i < idx+15; i++ ) {
            if ( keyAsArray[i] != seqiod[i-idx] ) {
                return nil
            }
        }
        idx += 15
        
        if (keyAsArray[idx++] != 0x03) {
            return nil
        }
        if (keyAsArray[idx] > 0x80) {
            idx += Int(keyAsArray[idx]) - 0x80 + 1;
        } else {
            idx++
        }
        
        if (keyAsArray[idx++] != 0x00) {
            return nil
        }
        
        var newArray = [UInt8](count: (keyAsArray.count - idx) / sizeof(UInt8), repeatedValue: 0)
        for ( var i = idx; i < keyAsArray.count; i++ ) {
            newArray[i-idx] = keyAsArray[i]
        }
        
        return NSData(bytes: newArray, length: newArray.count)
    }
    
    // Get a SecKeyRef from keychain
    static public func getRSAKeyFromKeychain(tagName: String) -> SecKeyRef? {
        var queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName,
            String(kSecReturnRef)         : true
        ]
        var keyPtr: Unmanaged<AnyObject>?
        var result = SecItemCopyMatching(queryFilter, &keyPtr)
        if ( result != noErr || keyPtr == nil ) {
            return nil
        }
        return (keyPtr!.takeRetainedValue() as! SecKeyRef)
    }
    
    // Add a pubic key to keychain and return its SecKeyRef
    static public func addPublicKey(pubkeyBase64: String, tagName: String) -> SecKeyRef? {
        return addPublicKey(pubkey: base64Decode(pubkeyBase64), tagName: tagName)
    }
    
    static private func addPublicKey(#pubkey: NSData, tagName: String) -> SecKeyRef? {
        var pubkeyData = stripPublicKeyHeader(pubkey)
        if ( pubkeyData == nil ) {
            return nil
        }
        
        // Delete any old lingering key with the same tag
        var queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName
        ]
        var result = SecItemDelete(queryFilter)
        
        var keyAsArray = [UInt8](count: pubkeyData!.length / sizeof(UInt8), repeatedValue: 0)
        pubkeyData!.getBytes(&keyAsArray, length: pubkeyData!.length)
        
        // Add persistent version of the key to system keychain
        //var prt1: Unmanaged<AnyObject>?
        queryFilter = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tagName,
            String(kSecValueData)          : pubkeyData!,
            String(kSecAttrKeyClass)       : kSecAttrKeyClassPublic,
            String(kSecReturnPersistentRef): true
        ]
        result = SecItemAdd(queryFilter, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }
        
        return getRSAKeyFromKeychain(tagName)
    }
    
    // Encrypts data with a public key
    static public func encryptWithPublicKey(data: NSData, pubkeyBase64: String, keychainTag: String) -> NSData? {
        var keyRef = getRSAKeyFromKeychain(keychainTag)
        if ( keyRef == nil ) {
            keyRef = addPublicKey(pubkeyBase64, tagName: keychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }
        
        let blockSize = SecKeyGetBlockSize(keyRef!)
        let maxChunkSize = blockSize - 11
        
        var decryptedDataAsArray = [UInt8](count: data.length / sizeof(UInt8), repeatedValue: 0)
        data.getBytes(&decryptedDataAsArray, length: data.length)
        
        var encryptedData = [UInt8](count: 0, repeatedValue: 0)
        var idx = 0
        while (idx < decryptedDataAsArray.count ) {
            var idxEnd = idx + maxChunkSize
            if ( idxEnd > decryptedDataAsArray.count ) {
                idxEnd = decryptedDataAsArray.count
            }
            var chunkData = [UInt8](count: maxChunkSize, repeatedValue: 0)
            for ( var i = idx; i < idxEnd; i++ ) {
                chunkData[i-idx] = decryptedDataAsArray[i]
            }
            
            var encryptedDataBuffer = [UInt8](count: blockSize, repeatedValue: 0)
            var encryptedDataLength = blockSize
            
            let status = SecKeyEncrypt(keyRef!, SecPadding(kSecPaddingPKCS1), chunkData, idxEnd-idx, &encryptedDataBuffer, &encryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            //let finalData = removePadding(encryptedDataBuffer)
            encryptedData += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        return NSData(bytes: encryptedData, length: encryptedData.count)
    }
    
    // Decrypt an encrypted data with a public key
    static public func decryptWithPublicKey(encryptedData: NSData, pubkeyBase64: String, keychainTag: String) -> NSData? {
        var keyRef = getRSAKeyFromKeychain(keychainTag)
        if ( keyRef == nil ) {
            keyRef = addPublicKey(pubkeyBase64, tagName: keychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }
        
        let blockSize = SecKeyGetBlockSize(keyRef!)
        
        var encryptedDataAsArray = [UInt8](count: encryptedData.length / sizeof(UInt8), repeatedValue: 0)
        encryptedData.getBytes(&encryptedDataAsArray, length: encryptedData.length)

        var decryptedData = [UInt8](count: 0, repeatedValue: 0)
        var idx = 0
        while (idx < encryptedDataAsArray.count ) {
            var idxEnd = idx + blockSize
            if ( idxEnd > encryptedDataAsArray.count ) {
                idxEnd = encryptedDataAsArray.count
            }
            var chunkData = [UInt8](count: blockSize, repeatedValue: 0)
            for ( var i = idx; i < idxEnd; i++ ) {
                chunkData[i-idx] = encryptedDataAsArray[i]
            }
            
            var decryptedDataBuffer = [UInt8](count: blockSize, repeatedValue: 0)
            var decryptedDataLength = blockSize
            
            let status = SecKeyDecrypt(keyRef!, SecPadding(kSecPaddingNone), chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            let finalData = removePadding(decryptedDataBuffer)
            decryptedData += finalData
            
            idx += blockSize
        }
        
        return NSData(bytes: decryptedData, length: decryptedData.count)
    }
    
    static private func removePadding(data: [UInt8]) -> [UInt8] {
        var idxFirstZero = -1
        var idxNextZero = data.count
        for ( var i = 0; i < data.count; i++ ) {
            if ( data[i] == 0 ) {
                if ( idxFirstZero < 0 ) {
                    idxFirstZero = i
                } else {
                    idxNextZero = i
                    break
                }
            }
        }
        var newData = [UInt8](count: idxNextZero-idxFirstZero-1, repeatedValue: 0)
        for ( var i = idxFirstZero+1; i < idxNextZero; i++ ) {
            newData[i-idxFirstZero-1] = data[i]
        }
        return newData
    }
}

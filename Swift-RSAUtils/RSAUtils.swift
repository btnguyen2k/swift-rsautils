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
// - http://hg.mozilla.org/services/fx-home/file/tip/Sources/NetworkAndStorage/CryptoUtils.m#l1036

import Foundation
import Security

public class RSAUtils: NSObject {
    // Base64 encode a block of data
    static private func base64Encode(data: NSData) -> String {
        return data.base64EncodedStringWithOptions([])
    }
    
    // Base64 decode a base64-ed string
    static private func base64Decode(strBase64: String) -> NSData {
        let data = NSData(base64EncodedString: strBase64, options: [])
        return data!
    }

    // Encrypts data with a RSA key
    static public func encryptWithRSAKey(data: NSData, rsaKeyRef: SecKeyRef, padding: SecPadding) -> NSData? {
        let blockSize = SecKeyGetBlockSize(rsaKeyRef)
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

            let status = SecKeyEncrypt(rsaKeyRef, padding, chunkData, idxEnd-idx, &encryptedDataBuffer, &encryptedDataLength)
            if ( status != noErr ) {
                NSLog("Error while ecrypting: %i", status)
                return nil
            }
            //let finalData = removePadding(encryptedDataBuffer)
            encryptedData += encryptedDataBuffer

            idx += maxChunkSize
        }

        return NSData(bytes: encryptedData, length: encryptedData.count)
    }

    // Decrypt an encrypted data with a RSA key
    static public func decryptWithRSAKey(encryptedData: NSData, rsaKeyRef: SecKeyRef, padding: SecPadding) -> NSData? {
        let blockSize = SecKeyGetBlockSize(rsaKeyRef)

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

            let status = SecKeyDecrypt(rsaKeyRef, padding, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
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

    // Verify that the supplied key is in fact a X509 public key and strip the header
    // On disk, a X509 public key file starts with string "-----BEGIN PUBLIC KEY-----",
    // and ends with string "-----END PUBLIC KEY-----"
    static private func stripPublicKeyHeader(pubkey: NSData) -> NSData? {
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

        return pubkey.subdataWithRange(NSMakeRange(idx, keyAsArray.count - idx))
    }

    // Verify that the supplied key is in fact a PEM RSA private key key and strip the header
    // On disk, a PEM RSA private key file starts with string "-----BEGIN RSA PRIVATE KEY-----",
    // and ends with string "-----END RSA PRIVATE KEY-----"
    static private func stripPrivateKeyHeader(privkey: NSData) -> NSData? {
        if ( privkey.length == 0 ) {
            return nil
        }

        var keyAsArray = [UInt8](count: privkey.length / sizeof(UInt8), repeatedValue: 0)
        privkey.getBytes(&keyAsArray, length: privkey.length)

        //magic byte at offset 22, check if it's actually ASN.1
        var idx = 22
        if ( keyAsArray[idx++] != 0x04 ) {
            return nil
        }
        //now we need to find out how long the key is, so we can extract the correct hunk
        //of bytes from the buffer.
        var len = Int(keyAsArray[idx++])
        let det = len & 0x80 //check if the high bit set
        if (det == 0) {
            //no? then the length of the key is a number that fits in one byte, (< 128)
            len = len & 0x7f
        } else {
            //otherwise, the length of the key is a number that doesn't fit in one byte (> 127)
            var byteCount = Int(len & 0x7f)
            if (byteCount + idx > privkey.length) {
                return nil
            }
            //so we need to snip off byteCount bytes from the front, and reverse their order
            var accum: UInt = 0
            var idx2 = idx
            idx += byteCount
            while (byteCount > 0) {
                //after each byte, we shove it over, accumulating the value into accum
                accum = (accum << 8) + UInt(keyAsArray[idx2++])
                byteCount--
            }
            // now we have read all the bytes of the key length, and converted them to a number,
            // which is the number of bytes in the actual key.  we use this below to extract the
            // key bytes and operate on them
            len = Int(accum)
        }

        return privkey.subdataWithRange(NSMakeRange(idx, len))
    }

    // Delete any existing RSA key from keychain
    static public func deleteRSAKeyFromKeychain(tagName: String) {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName
        ]
        SecItemDelete(queryFilter)
    }

    // Get a SecKeyRef from keychain
    static public func getRSAKeyFromKeychain(tagName: String) -> SecKeyRef? {
        let queryFilter: [String: AnyObject] = [
            String(kSecClass)             : kSecClassKey,
            String(kSecAttrKeyType)       : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag): tagName,
            //String(kSecAttrAccessible)    : kSecAttrAccessibleWhenUnlocked,
            String(kSecReturnRef)         : true
        ]

		var keyPtr: AnyObject?
        let result = SecItemCopyMatching(queryFilter, &keyPtr)
        if ( result != noErr || keyPtr == nil ) {
            return nil
        }
        return keyPtr as! SecKeyRef?
    }

    // Add a RSA private key to keychain and return its SecKeyRef
    // privkeyBase64: RSA private key in base64 (data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----")
    static public func addRSAPrivateKey(privkeyBase64: String, tagName: String) -> SecKeyRef? {
        return addRSAPrivateKey(privkey: base64Decode(privkeyBase64), tagName: tagName)
    }

    static private func addRSAPrivateKey(privkey privkey: NSData, tagName: String) -> SecKeyRef? {
        // Delete any old lingering key with the same tag
        deleteRSAKeyFromKeychain(tagName)

        let privkeyData = stripPrivateKeyHeader(privkey)
        if ( privkeyData == nil ) {
            return nil
        }

        // Add persistent version of the key to system keychain
        // var prt: AnyObject?
        let queryFilter = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tagName,
            //String(kSecAttrAccessible)     : kSecAttrAccessibleWhenUnlocked,
            String(kSecValueData)          : privkeyData!,
            String(kSecAttrKeyClass)       : kSecAttrKeyClassPrivate,
            String(kSecReturnPersistentRef): true
        ]
        let result = SecItemAdd(queryFilter, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }

        return getRSAKeyFromKeychain(tagName)
    }

    // Add a RSA pubic key to keychain and return its SecKeyRef
    // pubkeyBase64: RSA public key in base64 (data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----")
    static public func addRSAPublicKey(pubkeyBase64: String, tagName: String) -> SecKeyRef? {
        return addRSAPublicKey(pubkey: base64Decode(pubkeyBase64), tagName: tagName)
    }
    
    static private func addRSAPublicKey(pubkey pubkey: NSData, tagName: String) -> SecKeyRef? {
        // Delete any old lingering key with the same tag
        deleteRSAKeyFromKeychain(tagName)

        let pubkeyData = stripPublicKeyHeader(pubkey)
        if ( pubkeyData == nil ) {
            return nil
        }
        
        // Add persistent version of the key to system keychain
        //var prt1: Unmanaged<AnyObject>?
        let queryFilter = [
            String(kSecClass)              : kSecClassKey,
            String(kSecAttrKeyType)        : kSecAttrKeyTypeRSA,
            String(kSecAttrApplicationTag) : tagName,
            String(kSecValueData)          : pubkeyData!,
            String(kSecAttrKeyClass)       : kSecAttrKeyClassPublic,
            String(kSecReturnPersistentRef): true
        ]
        let result = SecItemAdd(queryFilter, nil)
        if ((result != noErr) && (result != errSecDuplicateItem)) {
            return nil
        }
        
        return getRSAKeyFromKeychain(tagName)
    }

    // Encrypt data with a RSA private key
    // privkeyBase64: RSA private key in base64 (data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----")
    // NOT WORKING YET!
    static public func encryptWithRSAPrivateKey(data: NSData, privkeyBase64: String, keychainTag: String) -> NSData? {
        let myKeychainTag = keychainTag + "-" + String(privkeyBase64.hashValue)
        var keyRef = getRSAKeyFromKeychain(myKeychainTag)
        if ( keyRef == nil ) {
            keyRef = addRSAPrivateKey(privkeyBase64, tagName: myKeychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }

        return encryptWithRSAKey(data, rsaKeyRef: keyRef!, padding: SecPadding.PKCS1)
    }

    // Encrypt data with a RSA public key
    // pubkeyBase64: RSA public key in base64 (data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----")
    static public func encryptWithRSAPublicKey(data: NSData, pubkeyBase64: String, keychainTag: String) -> NSData? {
        let myKeychainTag = keychainTag + "-" + String(pubkeyBase64.hashValue)
        var keyRef = getRSAKeyFromKeychain(myKeychainTag)
        if ( keyRef == nil ) {
            keyRef = addRSAPublicKey(pubkeyBase64, tagName: myKeychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }

        return encryptWithRSAKey(data, rsaKeyRef: keyRef!, padding: SecPadding.PKCS1)
    }

    // Decrypt an encrypted data with a RSA private key
    // privkeyBase64: RSA private key in base64 (data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----")
    static public func decryptWithRSAPrivateKey(encryptedData: NSData, privkeyBase64: String, keychainTag: String) -> NSData? {
        let myKeychainTag = keychainTag + "-" + String(privkeyBase64.hashValue)
        var keyRef = getRSAKeyFromKeychain(myKeychainTag)
        if ( keyRef == nil ) {
            keyRef = addRSAPrivateKey(privkeyBase64, tagName: myKeychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }

        return decryptWithRSAKey(encryptedData, rsaKeyRef: keyRef!, padding: SecPadding.None)
    }
    
    // Decrypt an encrypted data with a RSA public key
    // pubkeyBase64: RSA public key in base64 (data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----")
    static public func decryptWithRSAPublicKey(encryptedData: NSData, pubkeyBase64: String, keychainTag: String) -> NSData? {
        let myKeychainTag = keychainTag + "-" + String(pubkeyBase64.hashValue)
        var keyRef = getRSAKeyFromKeychain(myKeychainTag)
        if ( keyRef == nil ) {
            keyRef = addRSAPublicKey(pubkeyBase64, tagName: myKeychainTag)
        }
        if ( keyRef == nil ) {
            return nil
        }

        return decryptWithRSAKey(encryptedData, rsaKeyRef: keyRef!, padding: SecPadding.None)
    }
}

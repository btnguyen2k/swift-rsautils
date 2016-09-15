//
//  ViewController.swift
//  Swift-RSAUtils
//
//  Created by Thanh Nguyen on 7/10/15.
//  Copyright (c) 2015 Thanh Nguyen. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var txtTextToEncrypt: UITextField!
    
    @IBOutlet weak var txtEncryptedTextPubKey: UITextField!

    //RSA keys, 512 bits
    //PrivKey: MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqQS+aHr1ezKRKAQYYTfnhoMQnC5AAB8b2htKnzw+sIL47eTFgapJsNp7f658IxIlEEarOJ87IeWOZl/s51MvWQIDAQABAkBW8fLFKmN3YZbcP+cOs8RtJKT5wqz3owkf1KQ5b7NL9uyVvgRF/NMewm09qS3UBSkMmPOC+nwD83UEhEtj2ECBAiEA6PxlisxxG+aMNKLdIauovkqCfcH4Ppfxg502pPq/VJECIQC5tseG6pULWWit76tWKM+3Q/xSu6Os/lnB50o46SPySQIgdAEPsf8/JiwxjRe2UMh+uViyBlmo98mBqA2EIrryvvECIQCZ/kTuy7+w/H9/kzfIpuiud3JYC/2JqhM1ZRs3m6LR+QIge4zNJ81ddLqlna9VJRvNbz5WOw76JxY1+TLT8j88HzA=
    //PubKey : MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKkEvmh69XsykSgEGGE354aDEJwuQAAfG9obSp88PrCC+O3kxYGqSbDae3+ufCMSJRBGqzifOyHljmZf7OdTL1kCAwEAAQ==

    //RSA keys, 1024 bits
    //PrivKey: MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJPWWB5iPgb/WL2JDrNH15VwlpmhfXzKcS0qm+VT+uPbIoesuQ7Bggb7j7nEyQKWsiXIF5qBqlsPOE9WLbosoVZc36TqrhSIiLol2fkUVypZ61rgeAjNaoeCj4RhzMrNBQ7S+QF6r7DQq7zM4oX6o2KTbxosLbj/SIjBr4WX/WAvAgMBAAECgYARYhC2ceLNO9UZZDZASmBFCBoNMnno5HzuTKZMDtXfWPL0dRDFdWdunsHFnCfuj/2eh6qO1lRLpLyAR6fUzk6iBQx4kOG/FXnYQ+K/csJClPenplVZBpIA4gQkSneBd6HTg6OCA2u9FWWt+bcdi6KVwv2KOy/0tXQOleJk5BueIQJBANa7oEEbybxxImga3vXQ5JK8HltOVe3l8ZNo4P0E9s/V2QP9IbDngD7fAnYiRU9GOcAZ7aJMwjUFi0dQLm8KXicCQQCwP5q1lkeiRPsloLGfbmAdWgEfJEWURYz2wfgFLXxyi0KmSZ9gFNjDI/yZ9CsNB2c6eTYVAGT4WMggk7y7kbq5AkBaIjWZPsXGMKLlmeneuslHAmmnn9EX474sRwixjAThpnzKXNVogTPmsAtDdQ0swmh5RyjlSFz4jpQw4eort+lfAkEAmx/AOWcFsYrpSZr/+wUYz3yyVAiGvRPiGCVs+JGqYN61UMqn3dc7WbXI1HAVnCgR8WNR+HYaaIMr0ZB2otiG8QJAE4SENALs05ARJy/bvnmLY9xkkOmGRYgqfJWP/3Kjfjyfc2SOMpM6oMU7u+8YMj+Uw0ZF4ox7vO+mLsaBAvnByw==
    //PubKey : MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCT1lgeYj4G/1i9iQ6zR9eVcJaZoX18ynEtKpvlU/rj2yKHrLkOwYIG+4+5xMkClrIlyBeagapbDzhPVi26LKFWXN+k6q4UiIi6Jdn5FFcqWeta4HgIzWqHgo+EYczKzQUO0vkBeq+w0Ku8zOKF+qNik28aLC24/0iIwa+Fl/1gLwIDAQAB

    //RSA keys, 2048 bits
    //PrivKey: MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCaGgTgZ3zDElxHhiR90cOUQLlG2YpH+LpenhQwn+ZvoUoHzaWwPl0DYSIRBQQqDdm5hJvGLWSmnzJ2/49DgMyFtDXXxRrQTXvx/vfqSgZ8V50sCdBohgcbYpXGcSa7YG9zHMhLjNi+UFHj/01uVz2eMRrosedPw/XbBpCOTTb64xo6eMJLL3mFXUTMauVel4nzKBfepHKfPyPkABNMSSm2vKuVOkDqDrw9kkPULQROEEo+EabpwDVbLOysU8FB2LtFLEsDtSvOUxPqVvGvAL8d1ZtxBJRad6heapAtw/wxOILDb2Cb3swbuDzLvFbTo+MJfqnG2L0u3yNHL++Zz8ADAgMBAAECggEATa6iGLFybi+6Pv/7M0Xj7r815uZQ0/kpkfrkOKLSmiFXXVmolZDKeKKldqjtsXlr8R5NHHjTjT8hRGWNxbyO3TO8FLoyyyDUQ2iBdyS74kCUZZfI7Hfr6z0mPXPaz4hMhl3TBmrI9B8vON0BHodx82XTp8vOzCH/tNq5UlLQTWYXzQPajSsdKot7rTPcW6U5zQKuC+61DvHLKJ2R0pWiw/3UZpn8kvo/0B+PuHrcv8oJqOD9TfR6ZC8hHa2433cMKF9nzgoQCMawB96RVuKVMYa3OuXwaM3knoFY9icD4jUYVX1PUako9BjRx9QBK1trxCgiL4CL9H5ZBZm8nRJx4QKBgQDRxSgSgtSWKDurW9CilbH7fs94vI/47Cet2SPKxwRAmsfwCh8qgVyTFQAMrvlf+GMW2SOErVbQodhfYsn+A5d6z1DcO9A6zvpifRriF/lDneMbiGl8Yv1r24pARzGom9FFpEq6l8qzG7VCkpwEI7zQjE/HJujKu7iu6Q3P5X9YcwKBgQC8ECX8Y1Hjm02kcB40YCp8sy+ZO0IN7kVjUWSZK3i1jQ3b9CGYYZ9hDF67pqZuozipaRQeC1T48oFaiJWXSEReqYuuCBRRSU/OfQui8HWxucUprJrZ3IJOs9l1XtOmO0S0nNsq0wg2vvwW8XlVoP83gD6mzmDiMTxfRpAkEYZmMQKBgHLlQiWhcz8rmkMpbwUeaPYPZyQCY/k7oCAgpvISP8oC/TAE2z00zbfh8L0BuaVPLzb8h+/L4Zk0jIbyXSC8ZuPlWazHNi5/37TCQU9FQko+2H3kIaL3tUa2YOsEE7b+YYl7i1LYgTXJH2bvVnUN/gVcVPYH4cnpOCbVj7MnSLDxAoGAOBpdKqj6gfsPs5GbASb7Jc5S0dSixQMjAhkC+MrGLOsSil6PMyVUZaBKFpMFrZXVznxBeyEITWgS/M4oSkRN2SudNuLEJOfI/iHBue8gPU/dKKyMWZf168Ktid0rKLkfqv3sSB9CoQpiq/mHp+rqmEUS67I/ptrnVsj3MTtlK9ECgYEAoOW4YBPD2DoperiMWXSTLBB9ElsmJjIekFDjAVdyxZ4vfXo/FFfNTAD7CUhDggLf6escFLrUy8oh1xkOT1hK7C1UK0hOKF5qLNPQ5qNSV6LOFCWoONHy6C5QR698H1hBRTMJZHIo2L7FaR4ij9oy2fmWBAJ780f2hVMKKkgzJ9Y=
    //PubKey : MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmhoE4Gd8wxJcR4YkfdHDlEC5RtmKR/i6Xp4UMJ/mb6FKB82lsD5dA2EiEQUEKg3ZuYSbxi1kpp8ydv+PQ4DMhbQ118Ua0E178f736koGfFedLAnQaIYHG2KVxnEmu2BvcxzIS4zYvlBR4/9Nblc9njEa6LHnT8P12waQjk02+uMaOnjCSy95hV1EzGrlXpeJ8ygX3qRynz8j5AATTEkptryrlTpA6g68PZJD1C0EThBKPhGm6cA1WyzsrFPBQdi7RSxLA7UrzlMT6lbxrwC/HdWbcQSUWneoXmqQLcP8MTiCw29gm97MG7g8y7xW06PjCX6pxti9Lt8jRy/vmc/AAwIDAQAB

    // RSA public key in base64 / Key length: 512 bits
    let PUBLIC_KEY = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJh+/sdLdlVVcM5V5/j/RbwM8SL++Sc3dMqMK1nP73XYKhvO63bxPkWwaY0kwcUU40+QducwjueVOzcPFvHf+fECAwEAAQ=="
    
    // RSA private key in base64 / Key length: 512 bits
    let PRIVATE_KEY = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAmH7+x0t2VVVwzlXn+P9FvAzxIv75Jzd0yowrWc/vddgqG87rdvE+RbBpjSTBxRTjT5B25zCO55U7Nw8W8d/58QIDAQABAkBCNqIZlsKCut6IOPTIQM7eoB/zuhIk3QdxCvunu4mV+OIv00b6lN02ZsQ64nblu6dP9UuhlyclFaGlXtwqfkABAiEA0XQlb0mT5cZ8VpNNOqojeWoyrvQIRPGhdBrq3VroT4ECIQC6YoVd0yaT6lUDV+tgKtNbQN8m9hVIMgE/awRT/aXicQIhAK+jIbEMlgTcSG+g3eYPveeWciHbaQPHS4g8+i3ciWoBAiBddJsEwaQ9VKlN5N67uJ2DyxJZediP+6rOfr2L08pCsQIhAJLmeidBF0uJxNZiBgnkIHlRQ167qE1D0s5SQ2j5217G"
    
    // Sample text: "Thanh Nguyen - This is expected to be a longer-than-53-characters text"
    
    // Sample text, encrypted with public key
    let DATA_ENCRYPTED_WITH_PUBLIC_KEY = "jeX7CmYaORebxP9fTbeBxp0jAGJ0fxJ3pbL9lQ+29KAO+YtA1F3Dez1jCv2xQgK3uH7FtSDdEduc3drKwdOrcgTEVHqx+2GOAwq0654kzdgUWJKrpvCMQr3ttjT9Jbb50/xbIpXqKElscH301MAURj+JZsRTqYCJBtY+RYbIfcg="

    // Sample text, encrypted with private key
    let DATA_ENCRYPTED_WITH_PRIVATE_KEY = "eSeAcLggg5IYrGnA3JRgHB5jjEU3IlPce0q+1PM80Gzv6Fi722DH1DOZ3DUpgoQY2ZADBbRERdYSa+hxH9wDARtfpJn3huCAvc1e0p+G2tQ44GuXpC0CoYyeQ4MB1UH8zrPdL6NryQ2zSFp0JAt9u/6ZQWqE+fyafc+Zs68GumQ="
    
    // tag name to access the stored private key stored in keychain
    let TAG_PRIVATE_KEY = "com.github.btnguyen2k.Sample_Private"

    // tag name to access the stored public key in keychain
    let TAG_PUBLIC_KEY = "com.github.btnguyen2k.Sample_Public"

    override func viewDidLoad() {
        super.viewDidLoad()
        txtEncryptedTextPubKey.isEnabled = false
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @IBAction func doEncrypt() {
        txtEncryptedTextPubKey.text = ""
        
        let textToEncrypt = txtTextToEncrypt.text
        if ( textToEncrypt == nil || textToEncrypt == "" ) {
            txtEncryptedTextPubKey.text = "Please enter some text to encrypt"
            txtEncryptedTextPubKey.textColor = UIColor.red
            return
        }

        var encryptedData = RSAUtils.encryptWithRSAPublicKey(textToEncrypt!.data(using: String.Encoding.utf8)!, pubkeyBase64: PUBLIC_KEY, keychainTag: TAG_PUBLIC_KEY)
        if ( encryptedData == nil ) {
            txtEncryptedTextPubKey.text = "Error while encrypting"
            txtEncryptedTextPubKey.textColor = UIColor.red
        } else {
            let encryptedDataText = encryptedData!.base64EncodedString(options: NSData.Base64EncodingOptions())
            NSLog("Encrypted with pubkey: %@", encryptedDataText)
            txtEncryptedTextPubKey.text = encryptedDataText
            txtEncryptedTextPubKey.textColor = UIColor.blue
        }

        encryptedData = RSAUtils.encryptWithRSAPrivateKey(textToEncrypt!.data(using: String.Encoding.utf8)!, privkeyBase64: PRIVATE_KEY, keychainTag: TAG_PRIVATE_KEY)
        if ( encryptedData == nil ) {
        } else {
            let encryptedDataText = encryptedData!.base64EncodedString(options: NSData.Base64EncodingOptions())
            NSLog("Encrypted with privkey: %@", encryptedDataText)
        }

        var ENCRYPTED_DATA = DATA_ENCRYPTED_WITH_PRIVATE_KEY
        encryptedData = Data(base64Encoded: ENCRYPTED_DATA, options: NSData.Base64DecodingOptions())
        var decryptedData = RSAUtils.decryptWithRSAPublicKey(encryptedData!, pubkeyBase64: PUBLIC_KEY, keychainTag: TAG_PUBLIC_KEY)
        if ( decryptedData != nil ) {
            //let decryptedString = NSString(decryptedData!)
            //NSLogv("Data encrypted with privateKey: %@\nAfter decrypted with publicKey: %@", ENCRYPTED_DATA, decryptedString!);
        } else {
            NSLog("Error while decrypt string: %@\nusing publicKey: %@", ENCRYPTED_DATA, PUBLIC_KEY)
        }

        ENCRYPTED_DATA = DATA_ENCRYPTED_WITH_PUBLIC_KEY
        encryptedData = Data(base64Encoded: ENCRYPTED_DATA, options: NSData.Base64DecodingOptions())
        decryptedData = RSAUtils.decryptWithRSAPrivateKey(encryptedData!, privkeyBase64: PRIVATE_KEY, keychainTag: TAG_PRIVATE_KEY)
        if ( decryptedData != nil ) {
            //let decryptedString = NSString(data: decryptedData!, encoding:String.Encoding.utf8)
            //NSLog("Data encrypted with publicKey: %@\nAfter decrypted with privateKey: %@", ENCRYPTED_DATA, decryptedString!);
        } else {
            NSLog("Error while decrypt string: %@\nusing privateKey: %@", ENCRYPTED_DATA, PRIVATE_KEY)
        }
    }
    
}


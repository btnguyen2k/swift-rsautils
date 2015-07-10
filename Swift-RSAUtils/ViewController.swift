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
    
    // RSA public key in base64 / Key length: 512 bits
    let PUBLIC_KEY = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJh+/sdLdlVVcM5V5/j/RbwM8SL++Sc3dMqMK1nP73XYKhvO63bxPkWwaY0kwcUU40+QducwjueVOzcPFvHf+fECAwEAAQ=="
    
    // RSA private key in base64 / Key length: 512 bits
    let PRIVATE_KEY = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAmH7+x0t2VVVwzlXn+P9FvAzxIv75Jzd0yowrWc/vddgqG87rdvE+RbBpjSTBxRTjT5B25zCO55U7Nw8W8d/58QIDAQABAkBCNqIZlsKCut6IOPTIQM7eoB/zuhIk3QdxCvunu4mV+OIv00b6lN02ZsQ64nblu6dP9UuhlyclFaGlXtwqfkABAiEA0XQlb0mT5cZ8VpNNOqojeWoyrvQIRPGhdBrq3VroT4ECIQC6YoVd0yaT6lUDV+tgKtNbQN8m9hVIMgE/awRT/aXicQIhAK+jIbEMlgTcSG+g3eYPveeWciHbaQPHS4g8+i3ciWoBAiBddJsEwaQ9VKlN5N67uJ2DyxJZediP+6rOfr2L08pCsQIhAJLmeidBF0uJxNZiBgnkIHlRQ167qE1D0s5SQ2j5217G"
    
    // Sample text: "Thanh Nguyen - This is expected to be a longer-than-53-characters text"
    
    // Sample text, encrypted with public key
    let DATA_ENCRYPTED_WITH_PUBLIC_KEY = "NDgglMK2r3kp3/F6HAOPF8c571k6mqHdJ61lx6rTcX/gOvuo/xduB05kUvDBUbvTPNGRKUOamNv1OaJv1til+AOUjI8whuCZqceq8qvVqN0lQpv+c2vYL7LotrCYioZSybzyYbhkevqYtRm4CMk+T4pUS4tCmQxL3dK2nFJl9GE="

    // Sample text, encrypted with private key
    let DATA_ENCRYPTED_WITH_PRIVATE_KEY = "eSeAcLggg5IYrGnA3JRgHB5jjEU3IlPce0q+1PM80Gzv6Fi722DH1DOZ3DUpgoQY2ZADBbRERdYSa+hxH9wDARtfpJn3huCAvc1e0p+G2tQ44GuXpC0CoYyeQ4MB1UH8zrPdL6NryQ2zSFp0JAt9u/6ZQWqE+fyafc+Zs68GumQ="
    
    // tag name to access the stored private key stored in keychain
    let TAG_PRIVATE_KEY = "com.github.btnguyen2k.Sample_Private"

    // tag name to access the stored public key in keychain
    let TAG_PUBLIC_KEY = "com.github.btnguyen2k.Sample_Public"

    override func viewDidLoad() {
        super.viewDidLoad()
        txtEncryptedTextPubKey.enabled = false
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
            txtEncryptedTextPubKey.textColor = UIColor.redColor()
            return
        }
        
        var encryptedData = RSAUtils.encryptWithPublicKey((textToEncrypt as NSString).dataUsingEncoding(NSUTF8StringEncoding)!, pubkeyBase64: PUBLIC_KEY, keychainTag: TAG_PUBLIC_KEY)
        if ( encryptedData == nil ) {
            txtEncryptedTextPubKey.text = "Error while encrypting"
            txtEncryptedTextPubKey.textColor = UIColor.redColor()
            return
        }
        var encryptedDataText = encryptedData!.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.allZeros)
        println("Encrypt with pubkey: \(encryptedDataText)")
        txtEncryptedTextPubKey.text = encryptedDataText
        txtEncryptedTextPubKey.textColor = UIColor.blueColor()
     
//        let DATA = "aFhPGWbA5WCBfewPsx0AaxPUyipIrEJrTxS4FMKXmmcb2r/Mq6X1eLQ14eYhWi3Q3ViHvd7dA9atVbct/iXMvg=="
        let DATA = "eSeAcLggg5IYrGnA3JRgHB5jjEU3IlPce0q+1PM80Gzv6Fi722DH1DOZ3DUpgoQY2ZADBbRERdYSa+hxH9wDARtfpJn3huCAvc1e0p+G2tQ44GuXpC0CoYyeQ4MB1UH8zrPdL6NryQ2zSFp0JAt9u/6ZQWqE+fyafc+Zs68GumQ="
        encryptedData = NSData(base64EncodedString: DATA, options: NSDataBase64DecodingOptions.allZeros)
        let decryptedData = RSAUtils.decryptWithPublicKey(encryptedData!, pubkeyBase64: PUBLIC_KEY, keychainTag: TAG_PUBLIC_KEY)
        if ( decryptedData != nil ) {
            println(NSString(data: decryptedData!, encoding:NSUTF8StringEncoding))
        }
    }
    
}


Swift-RSAUtils
==============

RSA encryption and decryption with Swift iOS.

_Note: encryption with private key is currently not working!_

## This project is to solve the following problems (actually mine) ##

- Server had already generated a pair of public/private key, for example: public key `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJh+/sdLdlVVcM5V5/j/RbwM8SL++Sc3dMqMK1nP73XYKhvO63bxPkWwaY0kwcUU40+QducwjueVOzcPFvHf+fECAwEAAQ==`, and private key: `MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAmH7+x0t2VVVwzlXn+P9FvAzxIv75Jzd0yowrWc/vddgqG87rdvE+RbBpjSTBxRTjT5B25zCO55U7Nw8W8d/58QIDAQABAkBCNqIZlsKCut6IOPTIQM7eoB/zuhIk3QdxCvunu4mV+OIv00b6lN02ZsQ64nblu6dP9UuhlyclFaGlXtwqfkABAiEA0XQlb0mT5cZ8VpNNOqojeWoyrvQIRPGhdBrq3VroT4ECIQC6YoVd0yaT6lUDV+tgKtNbQN8m9hVIMgE/awRT/aXicQIhAK+jIbEMlgTcSG+g3eYPveeWciHbaQPHS4g8+i3ciWoBAiBddJsEwaQ9VKlN5N67uJ2DyxJZediP+6rOfr2L08pCsQIhAJLmeidBF0uJxNZiBgnkIHlRQ167qE1D0s5SQ2j5217G` and you (the iOS app) was given the public key as a base-64 text. You need to find a way to import this key pair into iOS keychain in order to use it.
- There is a solution in [Objective-C](https://github.com/ideawu/Objective-C-RSA) but I have found no solution in pure Swift (at the time I decided to write this small lib).
- RSA encryption/decryption does not allow you to process a large amount of data in one go. You have to split data into small chunks and encrypt/decrypt one by one and merge into the final result. This lib solves this problem as well.

### Functions ###

- `RSAUtils.encryptWithRSAKey(data: NSData, rsaKeyRef: SecKeyRef, padding: SecPadding) -> NSData?` encrypt data with a RSAKey. Currently not working with private key T_T
- `RSAUtils.decryptWithRSAKey(encryptedData: NSData, rsaKeyRef: SecKeyRef, padding: SecPadding) -> NSData?` decrypt data with a RSAKey (works with public & private key).
- `RSAUtils.deleteRSAKeyFromKeychain(tagName: String)` delete any existing RSA key from keychain
- `RSAUtils.getRSAKeyFromKeychain(tagName: String) -> SecKeyRef?` get a SecKeyRef from keychain
- `RSAUtils.addRSAPrivateKey(privkeyBase64: String, tagName: String) -> SecKeyRef?` add a RSA private key to keychain and return its SecKeyRef (private key data is in base64 encoding, the data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----").
- `RSAUtils.addRSAPublicKey(pubkeyBase64: String, tagName: String) -> SecKeyRef?` add a RSA pubic key to keychain and return its SecKeyRef (public key data is in base64 encoding, the data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----").
- `RSAUtils.encryptWithRSAPublicKey(data: NSData, pubkeyBase64: String, keychainTag: String) -> NSData?` encrypt data with a RSA public key (public key data is in base64 encoding, the data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----").
- `RSAUtils.decryptWithRSAPublicKey(encryptedData: NSData, pubkeyBase64: String, keychainTag: String) -> NSData?` decrypt an encrypted data with a RSA public key (public key data is in base64 encoding, the data between "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----").
- `RSAUtils.encryptWithRSAPrivateKey(data: NSData, privkeyBase64: String, keychainTag: String) -> NSData?` encrypt data with a RSA private key (private key data is in base64 encoding, the data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----"). The function is there but currently it is NOT WORKING YET!
- `RSAUtils.decryptWithRSAPrivateKey(encryptedData: NSData, privkeyBase64: String, keychainTag: String) -> NSData?` decrypt an encrypted data with a RSA private key (private key data is in base64 encoding, the data between "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----").


## History ##

### 2015-09-26 ###

- Code & Function cleanup, works with XCode 7 & Swift 2
- New functionality: decrypt with private key


### 2015-07-10 ###

- Encrypt & Decrypt data with public key.


## Licence ##

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

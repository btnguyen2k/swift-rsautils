Swift-RSAUtils
==============

RSA encryption and decryption with Swift iOS.

_Note:currently only encryption and decription with public key is support!_

### If you have the same problem(s) as mine: ###

- Server had already generated a pair of public/private key, for example: public key `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJh+/sdLdlVVcM5V5/j/RbwM8SL++Sc3dMqMK1nP73XYKhvO63bxPkWwaY0kwcUU40+QducwjueVOzcPFvHf+fECAwEAAQ==`, and private key: `MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAmH7+x0t2VVVwzlXn+P9FvAzxIv75Jzd0yowrWc/vddgqG87rdvE+RbBpjSTBxRTjT5B25zCO55U7Nw8W8d/58QIDAQABAkBCNqIZlsKCut6IOPTIQM7eoB/zuhIk3QdxCvunu4mV+OIv00b6lN02ZsQ64nblu6dP9UuhlyclFaGlXtwqfkABAiEA0XQlb0mT5cZ8VpNNOqojeWoyrvQIRPGhdBrq3VroT4ECIQC6YoVd0yaT6lUDV+tgKtNbQN8m9hVIMgE/awRT/aXicQIhAK+jIbEMlgTcSG+g3eYPveeWciHbaQPHS4g8+i3ciWoBAiBddJsEwaQ9VKlN5N67uJ2DyxJZediP+6rOfr2L08pCsQIhAJLmeidBF0uJxNZiBgnkIHlRQ167qE1D0s5SQ2j5217G` and you (the iOS app) was given the public key as a base-64 text.
- There is a solution in [Objective-C](https://github.com/ideawu/Objective-C-RSA) but I have found no solution in pure Swift (at the time I decide to write this small lib).
- RSA encryption/decryption does not allow you to process a large amount of data in one go. You have to split data into small chunks and encrypt/decrypt one by one and merge into the final result.

### Licence ###

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

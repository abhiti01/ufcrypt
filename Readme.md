# CNT 5410: Assignment 2

# Report

## Abhiti Sachdeva

## 1 Introduction

This program is a file encryption/decryption/transmission suite akin to scp using OpenSSL libraries provided by
the Linux operating system. The file encryption programs ufsend and ufrec take the following inputs:

```
ufsend < input file > [-d < IP-addr:port > ][ -l ]
ufrec < filename > [-d < port > ][ -l ]
```
ufsend takes an input file and transmits it to the IP address/port specified on the command-line (-d option), or dumps the encrypted contents of the input file to an output file of the same name, but with the added
extension “.ufsec”. ufrec either runs as a network daemon (-d), awaiting incoming network connections on the
command-line specified network port. When a connection comes in, it writes the file data to “filename” and
exits, or ufrec runs in local mode (-l) in which it bypasses the network functionality and simply decrypts a file
specified as input. The output will be the original filename without this additional extension.

On each invocation, ufsend and ufrec prompt the user for a password. This password will be used to securely generate an encryption using PBKDF2 (Password Based Key Derivation Function 2). When running PBKDF2, SHA-512 with 4096 iterations were used and the string “CalciumChloride” was used as the salt.

## 2 Program design

To obtain the key from a password input, the function PKCS5_PBKDF2_HMAC was used. This function
derives a key from a password using a salt and iteration count as specified in RFC 2898. The encryption and decryption processes required initialisation of an EVP_CIPHER object, for this program EVP_aes_256_gcm() was used. It uses the AES algorithm with a 256-bit key in GCM mode.


## 3 Conclusion

Although this program works as intended, using it is still far from secure. The IV that is generated “randomly”
is never truly random. It can be brute forced easily. Adding to this, the string used for key derivation should
not be hard-coded. It can be guessed by attackers easily. Making these changes along with increasing the
encryption/decryption capacity of this program will improve it’s performance greatly.



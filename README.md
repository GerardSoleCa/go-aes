# AES with KeyDerivation

Thin code implementing the OpenSSL key derivation. Developed due to have backward compatibility with NodeJS API where default createCipher for aes use OpenSSL key derivation [EVP_BytesToKey](https://www.openssl.org/docs/manmaster/crypto/EVP_BytesToKey.html)

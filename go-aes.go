package go_aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"crypto/md5"
)

func Encrypt(bytes []byte, key string) ([]byte, error) {
	derivatedKey, _ := derivateKey([]byte(key), []byte{})
	block, _ := aes.NewCipher(derivatedKey.key)

	cbc := cipher.NewCBCEncrypter(block, derivatedKey.iv)
	cbc.CryptBlocks(bytes, bytes)
	return pkcs7Unpad(bytes, aes.BlockSize)
}

func Decrypt(bytes []byte, key string) ([]byte, error) {
	derivatedKey, _ := derivateKey([]byte(key), []byte{})
	block, _ := aes.NewCipher(derivatedKey.key)

	//if err != nil {
	//	fmt.Println("Error: NewCipher(%d bytes) = %s", len(keyBytes.key), err)
	//	os.Exit(-1)
	//}

	cbc := cipher.NewCBCDecrypter(block, derivatedKey.iv)
	cbc.CryptBlocks(bytes, bytes)
	return pkcs7Unpad(bytes, aes.BlockSize)
}

type openSSLCreds struct {
	key []byte
	iv  []byte
}

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func derivateKey(password, salt []byte) (openSSLCreds, error) {
	m := make([]byte, 48)
	prev := []byte{}
	for i := 0; i < 3; i++ {
		prev = hash(prev, password, salt)
		copy(m[i * 16:], prev)
	}
	return openSSLCreds{key: m[:32], iv: m[32:]}, nil
}

/*
	Remove the trailing padding from the decrypted data chunk
 */
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data) % blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data) - 1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data) - padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data) - padlen], nil
}

func md5sum(d []byte) []byte {
	h := md5.New()
	h.Write(d)
	return h.Sum(nil)
}
func hash(prev, password, salt []byte) []byte {
	a := make([]byte, len(prev) + len(password) + len(salt))
	copy(a, prev)
	copy(a[len(prev):], password)
	copy(a[len(prev) + len(password):], salt)
	return md5sum(a)
}


// TODO: Try to merge with sizeable key size
//func evpBytesToKey(password string, keyLen int) (key []byte) {
//	const md5Len = 16
//
//	cnt := (keyLen - 1) / md5Len + 1
//	m := make([]byte, cnt * md5Len)
//	copy(m, md5sum([]byte(password)))
//
//	// Repeatedly call md5 until bytes generated is enough.
//	// Each call to md5 uses data: prev md5 sum + password.
//	d := make([]byte, md5Len + len(password))
//	start := 0
//	for i := 1; i < cnt; i++ {
//		start += md5Len
//		copy(d, m[start - md5Len:start])
//		copy(d[md5Len:], password)
//		copy(m[start:], md5sum(d))
//	}
//	return m[:keyLen]
//}

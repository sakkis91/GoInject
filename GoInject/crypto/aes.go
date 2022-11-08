package crypto

import (     
    "crypto/aes"
    "crypto/cipher"
    "encoding/hex"
    "crypto/rand"
    "crypto/md5"
    "io"
)

func EncryptAES(shellcode []byte, passphrase string) string {
	block, _ := aes.NewCipher(createHash(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, shellcode, nil)
	ciphertextToHex := hex.EncodeToString(ciphertext)
	return ciphertextToHex
}

func DecryptAES(encShellcode string, passphrase string) []byte {
	encShellcodeToBytes, _ := hex.DecodeString(encShellcode)
	key := createHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encShellcodeToBytes[:nonceSize], encShellcodeToBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
    
	return plaintext
}

func createHash(key string) []byte {
	hashalg := md5.New()
	hashalg.Write([]byte(key))
	md5hash := []byte(hex.EncodeToString(hashalg.Sum(nil)))
	return md5hash
}
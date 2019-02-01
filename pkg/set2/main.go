package set2

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"github.com/xiaket/cryptopals/pkg/lib"
)

func Prob9() {
	const message = "YELLOW SUBMARINE"
	padded := lib.PKCS7Padding([]byte(message), 20)
	fmt.Println(padded)
}

func Prob10() {
	const key = "YELLOW SUBMARINE"
	iv := make([]byte, aes.BlockSize)
	decrypted := prob10([]byte(key), iv)
	fmt.Printf("%s", decrypted)
}

func prob10(key, iv []byte) []byte {
	content := string(bytes.Join(lib.OpenFile("10"), []byte("")))
	cipherText, _ := base64.StdEncoding.DecodeString(content)
	return lib.DecryptCBC(cipherText, key, iv)
}

func Prob11() {
	encrypted := lib.EncryptionOracle([]byte("This is the secret in plaintext."))
	fmt.Println(encrypted)
}
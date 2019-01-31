package solutions

import "bytes"
import "crypto/aes"
import "encoding/base64"
import "fmt"

func Prob9() {
	const message = "YELLOW SUBMARINE"
	padded := PKCS7Padding([]byte(message), 20)
	fmt.Println(padded)
}

func Prob10() {
	const key = "YELLOW SUBMARINE"
	iv := make([]byte, aes.BlockSize)
	decrypted := prob10([]byte(key), iv)
	fmt.Printf("%s", decrypted)
}

func prob10(key, iv []byte) []byte {
	content := string(bytes.Join(OpenFile("10"), []byte("")))
	cipherText, _ := base64.StdEncoding.DecodeString(content)
	return DecryptCBC(cipherText, key, iv)
}

func Prob11() {
	encrypted := EncryptionOracle([]byte("This is the secret in plaintext."))
	fmt.Println(encrypted)
}

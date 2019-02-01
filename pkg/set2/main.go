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
	// We do have a requirement on the text, it should have a certain amount of repetition in it.
	for i := 0; i < 5; i++ {
		encrypted, mode := lib.EncryptionOracle([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))
		detected := lib.DetectionOracle(encrypted)
		fmt.Println(mode, detected == mode)
	}
}

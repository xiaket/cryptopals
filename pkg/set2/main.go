package set2

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"github.com/deckarep/golang-set"
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
	required := mapset.NewSetFromSlice([]interface{}{"ECB", "CBC"})
	recorded := mapset.NewSet()
	for true {
		encrypted, mode := lib.EncryptionOracle([]byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE"))
		detected := lib.DetectionOracle(encrypted)
		if detected != mode {
			panic("detection failed")
		}
		recorded.Add(mode)
		if recorded.Equal(required) {
			break
		}
	}
}

func Prob12() {
	key := lib.GenerateKey(16)
	unknownSrc := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknown, _ := base64.StdEncoding.DecodeString(unknownSrc)
	encrypt := func(payload []byte) []byte {
		message := append(payload, unknown...)
		return lib.EncryptECB(lib.PKCS7Padding(message, 16), key)
	}
	lib.AttackECB(encrypt)
}

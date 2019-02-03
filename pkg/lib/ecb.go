package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

type fn func([]byte) []byte

// AttackECB will decipher a string encrypted by AES-ECB without the encryption key.
func AttackECB(encrypt fn) []byte {
	blockSize, _ := DetectBlockSize(encrypt)
	return []byte("null")
}

func AttachNextByte(size int, suffix []byte, encrypt fn) byte {
	return []byte(" ")
}

// Detect block size for data encrypted with AES-ECB
func DetectBlockSize(encrypt fn) (int, error) {
	for i := 0; i < 1024; i++ {
		payload := []byte(strings.Repeat("T", i))
		if DetectECB(encrypt(payload)) {
			if i%2 == 0 {
				return i / 2, nil
			} else {
				// We are lucky, we got the first byte right.
				return (i + 1) / 2, nil
			}
		}
	}
	return -1, errors.New("Failed to determine")
}

// DetectECB will detect whether an byte array is encrypted with ECB
func DetectECB(data []byte) bool {
	trunks := make([][]byte, len(data)/16)
	for i := 0; i < len(data)/16; i++ {
		trunk := data[i*16 : (i+1)*16]
		for _, item := range trunks {
			if bytes.Equal(item, trunk) {
				return true
			}
		}
		trunks = append(trunks, trunk)
	}
	return false
}

// DecryptECB will decrypt text encrypted using a AES-128 running ECB mode using
// a provided key.
func DecryptECB(cipherText []byte, key []byte, blockSize int) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(cipherText))

	for bs, be := 0, blockSize; bs < len(cipherText); bs, be = bs+blockSize, be+blockSize {
		cipher.Decrypt(decrypted[bs:be], cipherText[bs:be])
	}
	return decrypted
}

// EncryptECB will encrypt a message using ECB with a key and return it
func EncryptECB(message []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)

	ciphertext := make([]byte, len(message))
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, message)
	return ciphertext
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// ECBEncrypter encrypt a message with a key using ECB mod
func ECBEncrypter(key, plaintext []byte) []byte {
	block, _ := aes.NewCipher(key)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

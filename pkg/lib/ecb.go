package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// DecryptECB will decrypt text encrypted using a AES-128 running ECB mode using
// a provided key.
func DecryptECB(cipherText []byte, key []byte, block_size int) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(cipherText))

	for bs, be := 0, block_size; bs < len(cipherText); bs, be = bs+block_size, be+block_size {
		cipher.Decrypt(decrypted[bs:be], cipherText[bs:be])
	}
	return decrypted
}

// DetectECB will detect whether an hex encoded string is encrypted with ECB
func DetectECB(line string) bool {
	// a hex string represents 4 bits, so 16 * 8 / 4 = 32 hex chars will
	// represent a 16 bytes trunk
	trunks := make([]string, len(line)/32)
	duplication := 0
	for i := 0; i < len(line)/32; i++ {
		trunk := line[i*32 : (i+1)*32]
		found := false
		for _, item := range trunks {
			if item == trunk {
				found = true
			}
		}
		if found {
			duplication += 1
		} else {
			trunks = append(trunks, trunk)
		}
	}
	return float64(duplication)/float64(len(line)/32) > 0.1
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

/*
func DecryptECB(cipherText []byte, key []byte, block_size int) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(cipherText))

	for bs, be := 0, block_size; bs < len(cipherText); bs, be = bs+block_size, be+block_size {
		cipher.Decrypt(decrypted[bs:be], cipherText[bs:be])
	}
	return decrypted
}*/

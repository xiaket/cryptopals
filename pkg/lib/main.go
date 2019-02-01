package lib

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"
)

// Common utils used by all problem sets.

// gitRootDir will find the root directory of this repo.
func gitRootDir() (bool, string) {
	dir, _ := filepath.Abs(".")
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "/.git")); err == nil {
			return true, dir
		}
		dir = filepath.Dir(dir)
	}
	return false, ""
}

// OpenFile will open a file specified by an index and return its content as
// an array of strings.
func OpenFile(number string) [][]byte {
	_, root := gitRootDir()
	inFile, _ := os.Open(filepath.Join(root, "assets", "file."+number+".txt"))
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	var content [][]byte

	for scanner.Scan() {
		content = append(content, []byte(scanner.Text()))
	}
	return content
}

// Set1 functions.

// CalcRating calculate the rating of a string based on letter frequency.
// The higher the rating, the more likely the string is a sentence in English.
func CalcRating(msg []byte) float64 {
	// Source: http://www.macfreek.nl/memory/Letter_Distribution
	var frequency = map[byte]float64{
		'a': 0.08023,
		'b': 0.01556,
		'c': 0.02773,
		'd': 0.04104,
		'e': 0.12510,
		'f': 0.02414,
		'g': 0.02003,
		'h': 0.05953,
		'i': 0.07021,
		'j': 0.00140,
		'k': 0.00697,
		'l': 0.04109,
		'm': 0.02470,
		'n': 0.06983,
		'o': 0.07592,
		'p': 0.01840,
		'q': 0.00108,
		'r': 0.06087,
		's': 0.06521,
		't': 0.09195,
		'u': 0.02810,
		'v': 0.00965,
		'w': 0.02069,
		'x': 0.00183,
		'y': 0.01800,
		'z': 0.00073,
		' ': 0.22426, // 18.317 / 10.218 * 12.510
	}
	rating := 0.0
	for _, ch := range msg {
		switch {
		case ch < 32:
			// Bad characters, a big minus.
			rating += -0.5
		case (ch >= 33 && ch < 47) || (ch >= 58 && ch < 65) || (ch >= 91 && ch < 96):
			// symbols, a little minus.
			rating += -0.05
		case ch >= 48 && ch < 57:
			// digits, a little plus.
			rating += 0.01
		default:
			lowered_character := bytes.ToLower([]byte{ch})[0]
			rating += frequency[lowered_character]
		}
	}
	return rating / float64(len(msg))
}

// DecryptSingleByteXOR will decrypt an array of bytes encrypted using
// single byte xor
func DecryptSingleByteXOR(message []byte) (byte, []byte) {
	var char byte
	guess := make([]byte, len(message))
	max := -1.0
	for suspect := 1; suspect < 128; suspect++ {
		XORByte(guess, message, byte(suspect))
		rating := CalcRating(guess)
		if rating > max {
			max = rating
			char = byte(suspect)
		}
	}
	XORByte(guess, message, char)
	return char, guess
}

func Transpose(blocks [][]byte, keysize int) [][]byte {
	remains := len(blocks[len(blocks)-1])
	transposed := make([][]byte, keysize)
	for i := range transposed {
		if i < remains {
			transposed[i] = make([]byte, len(blocks))
		} else {
			transposed[i] = make([]byte, len(blocks)-1)
		}
	}
	for i, block := range blocks {
		for j, byte_ := range block {
			transposed[j][i] = byte_
		}
	}
	return transposed
}

// Decode a hex buffer. return the decoded message and the count of bytes in the decoded message.
func HexDecode(message []byte) ([]byte, int) {
	decoded := make([]byte, hex.DecodedLen(len(message)))
	n, _ := hex.Decode(decoded, []byte(message))
	return decoded, n
}

// FindKeySize will find the key size in ciphertext protected using
// repeating-key XOR.
func FindKeySize(data []byte) int {
	min := float64(100)
	keysize := 0
	for size := 2; size <= 64; size++ {
		distance := 0
		trunks := len(data)/size - 2
		for i := 0; i < trunks; i++ {
			distance += HammingDistance(data[i*size:(i+1)*size], data[(i+1)*size:(i+2)*size])
		}
		norm_distance := float64(distance) / float64(size) / float64(trunks)
		if norm_distance < min {
			keysize = size
			min = norm_distance
		}
	}
	return keysize
}

// HammingDistance calculate the Hamming Distance of two byte arrays.
func HammingDistance(message1, message2 []byte) int {
	bin1 := Msg2Bin(message1)
	bin2 := Msg2Bin(message2)
	counts := 0
	for i, ch := range bin1 {
		if byte(ch) != bin2[i] {
			counts += 1
		}
	}
	return counts
}

// HexToBase64 encode a byte array in hex using base64.
func HexToBase64(hex_bytes []byte) []byte {
	bin, _ := HexDecode(hex_bytes)
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(bin)))
	base64.StdEncoding.Encode(dst, bin)
	return dst
}

// convert all bytes in a byte array to their binary representation.
func Msg2Bin(msg []byte) string {
	result := ""
	for _, ch := range msg {
		result = fmt.Sprintf("%s%.8b", result, ch)
	}
	return result
}

// XORByte uses a single byte(b) to run a xor operation on all the bytes in a
func XORByte(dst []byte, a []byte, b byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b
	}
	return n
}

// XORByte uses an array of bytes(b) to run a xor operation on all the bytes in a
func XORBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i%len(b)]
	}
	return n
}

// Set2 functions.

// DecryptCBC will decrypt text encrypted using a AES-128 running CBC mode using
// a provided key.
func DecryptCBC(cipherText, key, iv []byte) []byte {
	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(cipherText, cipherText)
	return cipherText
}

// GenerateKey generates a crypto-secure key
func GenerateKey(length int) []byte {
	key := make([]byte, length)
	rand.Read(key)
	return key
}

// PKCS7Padding implements PKCS#7 padding scheme.
func PKCS7Padding(msg []byte, length int) []byte {
	padding := length - (len(msg) % length)
	for i := 0; i < padding; i++ {
		msg = append(msg, byte(padding))
	}
	return msg
}

// Return a random int in the range [start, end)
// Based on math/rand, not crypto safe.
func RandInt(start, end int) int {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return r.Intn(end-start) + start
}

// PadMessage will padding a message as bytes with random bytes.
func PadMessage(paddingMin, paddingMax int, message []byte) []byte {
	seed, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	mrand.Seed(seed.Int64())
	paddingLeft := RandInt(paddingMin, paddingMax)
	paddingRight := RandInt(paddingMin, paddingMax)
	message = append(GenerateKey(paddingLeft), message...)
	return append(message, GenerateKey(paddingRight)...)
}

// EncryptCBC will encrypt a message using CBC with a key and an IV and return it
func EncryptCBC(message []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)

	ciphertext := make([]byte, aes.BlockSize+len(message))
	iv := ciphertext[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], message)
	return ciphertext
}

// EncryptionOracle is a function that generate a random key and encrypt data under it.
func EncryptionOracle(msg []byte) []byte {
	mode := ""
	var CipherText []byte
	key := GenerateKey(16)
	msg = PadMessage(5, 10, msg)
	msg = PKCS7Padding(msg, aes.BlockSize)

	if RandInt(0, 2) == 1 {
		mode = "ECB"
		CipherText = EncryptECB(msg, key)
	} else {
		mode = "CBC"
		CipherText = EncryptCBC(msg, key)
	}
	fmt.Println("use ", mode)
	return CipherText
}

// CBCEncrypter encrypt a message with a key using CBC mod
func CBCEncrypter(key, plaintext []byte) []byte {
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

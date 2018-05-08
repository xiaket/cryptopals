package solutions

import "bufio"
import "bytes"
import "crypto/aes"
import "encoding/hex"
import "encoding/base64"
import "fmt"
import "os"
import "path/filepath"

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
	_, git_root := gitRootDir()
	inFile, _ := os.Open(filepath.Join(git_root, "solutions", "file."+number+".txt"))
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

// DecryptSingleByteXOR will decrypt an array of bytes encrypted using
// single byte xor
func DecryptSingleByteXOR(message []byte) (byte, []byte) {
	var best_guess byte
	dst := make([]byte, len(message))
	max := -1.0
	for suspect := 1; suspect < 128; suspect++ {
		XORByte(dst, message, byte(suspect))
		rating := CalcRating(dst)
		if rating > max {
			max = rating
			best_guess = byte(suspect)
		}
	}
	XORByte(dst, message, best_guess)
	return best_guess, dst
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
func HexToBase64(hex_bytes []byte) string {
	bin := make([]byte, hex.DecodedLen(len(hex_bytes)))
	hex.Decode(bin, hex_bytes)
	encoded := base64.StdEncoding.EncodeToString(bin)
	return encoded
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

func PKCS7Padding(msg []byte, length int) []byte {
	padding := length - len(msg)
	for i := 0; i < padding; i++ {
		msg = append(msg, byte(padding))
	}
	return msg
}

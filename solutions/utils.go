package solutions

import "bufio"
import "encoding/hex"
import "encoding/base64"
import "os"
import "path/filepath"
import "strconv"
import "strings"

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
			lowered_character := []byte(strings.ToLower(string(ch)))[0]
			rating += frequency[lowered_character]
		}
	}
	return rating / float64(len(msg))
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

// msg2bin converts a message in string to another string, where all of
func msg2bin(msg []byte) string {
	bin_ := ""
	for _, byte_ := range msg {
		converted := strconv.FormatInt(int64(byte_), 2)
		converted = strings.Repeat("0", 8-len(converted)) + converted
		bin_ += converted
	}
	return bin_
}

// DecodeHex is a thin wrapper around hex.Decode to accept a string as input.
func DecodeHex(msg string) []byte {
	src := []byte(msg)
	bin := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(bin, src)
	return bin
}

// HammingDistance calculate the Hamming Distance of two strings.
func HammingDistance(message1, message2 []byte) int {
	bin1 := msg2bin(message1)
	bin2 := msg2bin(message2)
	counts := 0
	for i, ch := range bin1 {
		if byte(ch) != bin2[i] {
			counts += 1
		}
	}
	return counts
}

// HexToBase64 encode a string in hex using base64.
func HexToBase64(hex_string string) string {
	bin := DecodeHex(hex_string)
	encoded := base64.StdEncoding.EncodeToString(bin)
	return encoded
}

// DecryptSingleByteXOR will decrypt an array of bytes encrypted using
// single byte xor
func DecryptSingleByteXOR(message []byte) (byte, string) {
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
	decoded := string(dst)
	return best_guess, decoded
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

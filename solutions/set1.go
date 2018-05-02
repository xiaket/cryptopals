package solutions

import "crypto/aes"
import "encoding/base64"
import "encoding/hex"
import "fmt"
import "math"

// import "os"
import "strings"
import "../lib"

func Prob1() {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	encoded := cryptopals.HexToBase64(hex_string)
	fmt.Println(encoded)
}

func Prob2() {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	encodedStr := prob2(msg1, msg2)
	fmt.Println(encodedStr)
}

func prob2(msg1, msg2 string) string {
	bin1 := cryptopals.DecodeHex(msg1)
	bin2 := cryptopals.DecodeHex(msg2)
	fmt.Println(bin1)
	fmt.Println(bin2)

	dst := make([]byte, len(bin1))
	cryptopals.XORBytes(dst, bin1, bin2)
	encodedStr := hex.EncodeToString(dst)
	return encodedStr
}

func Prob3() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed := make([]byte, hex.DecodedLen(len(message)))
	n, _ := hex.Decode(unhexed, []byte(message))
	unhexed_ := unhexed[:n]

	_, guess := cryptopals.DecryptSingleByteXOR(unhexed_)
	fmt.Println(guess)
}

func Prob4() {
	guess := prob4()
	fmt.Println(guess)
}

func prob4() string {
	content := cryptopals.OpenFile("04")
	max := 0.0
	best_guess := ""

	for _, line := range content {
		unhexed, _ := hex.DecodeString(line)
		dst := make([]byte, len(unhexed))
		for suspect := 32; suspect < 128; suspect++ {
			cryptopals.XORByte(dst, unhexed, byte(suspect))
			rating := cryptopals.CalcRating(dst)
			if rating > max {
				max = rating
				best_guess = string(dst)
			}
		}
	}
	return strings.TrimRight(best_guess, "\n")
}

func Prob5() {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	encodedStr := prob5(message, key)
	fmt.Println(encodedStr)
}

func prob5(message, key string) string {
	xored := make([]byte, len(message))
	cryptopals.XORBytes(xored, []byte(message), []byte(key))
	return hex.EncodeToString(xored)
}

func findKeySize(data []byte) int {
	min := float64(100)
	keysize := 0
	for size := 2; size <= 40; size++ {
		distance := 0
		trunks := len(data)/size - 2
		for i := 0; i < trunks; i++ {
			distance += cryptopals.HammingDistance(data[i*size:(i+1)*size], data[(i+1)*size:(i+2)*size])
		}
		norm_distance := float64(distance) / float64(size) / float64(trunks)
		if norm_distance < min {
			keysize = size
			min = norm_distance
		}
	}
	return keysize
}

func transpose(blocks [][]byte, keysize int) [][]byte {
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

func prob6() (string, string) {
	content := strings.Join(cryptopals.OpenFile("06"), "")
	data, _ := base64.StdEncoding.DecodeString(content)
	keysize := findKeySize(data)

	blocks := [][]byte{}
	for i := 0; float64(i) < math.Ceil(float64(len(data))/float64(keysize)); i++ {
		upper_limit := int(math.Min(float64((i+1)*keysize), float64(len(data))))
		blocks = append(blocks, data[i*keysize:upper_limit])
	}
	transposed := transpose(blocks, keysize)

	var encryption_key string
	for i := range transposed {
		guess, _ := cryptopals.DecryptSingleByteXOR(transposed[i])
		encryption_key += string(guess)
	}
	plain_text := make([]byte, len(data))
	cryptopals.XORBytes(plain_text, []byte(data), []byte(encryption_key))
	return encryption_key, string(plain_text)
}

func Prob6() {
	encryption_key, _ := prob6()
	fmt.Println(encryption_key)
}

func prob7(key string, block_size int) string {
	content := strings.Join(cryptopals.OpenFile("07"), "")
	cipher, _ := aes.NewCipher([]byte(key))
	cipherText, _ := base64.StdEncoding.DecodeString(content)
	decrypted := make([]byte, len(cipherText))

	for bs, be := 0, block_size; bs < len(cipherText); bs, be = bs+block_size, be+block_size {
		cipher.Decrypt(decrypted[bs:be], cipherText[bs:be])
	}
	return string(decrypted)
}

func Prob7() {
	decrypted := prob7("YELLOW SUBMARINE", 16)
	fmt.Println(string(decrypted))
}

// detectECB will detect whether an hex encoded string is encrypted with ECB
func detectECB(line string) bool {
	trunks := make([]string, len(line)/4)
	duplication := 0
	for i := 0; i < len(line)/4; i++ {
		trunk := line[i*4 : (i+1)*4]
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
	return float64(duplication)/float64(len(line)) > 0.05
}

func Prob8() {
	lines := cryptopals.OpenFile("08")
	for _, line := range lines {
		if detectECB(line) {
			fmt.Println(line)
		}
	}
}

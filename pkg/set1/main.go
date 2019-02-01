package set1

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/xiaket/cryptopals/pkg/lib"
	"math"
)

func Prob1() {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	encoded := lib.HexToBase64([]byte(hex_string))
	fmt.Println(string(encoded))
}

func Prob2() {
	msg1 := []byte("1c0111001f010100061a024b53535009181c")
	msg2 := []byte("686974207468652062756c6c277320657965")
	encoded := prob2(msg1, msg2)
	fmt.Println(string(encoded))
}

func prob2(msg1, msg2 []byte) []byte {
	bin1, n1 := lib.HexDecode(msg1)
	bin2, _ := lib.HexDecode(msg2)

	dst := make([]byte, n1)
	lib.XORBytes(dst, bin1, bin2)

	encoded := make([]byte, hex.EncodedLen(len(dst)))
	hex.Encode(encoded, dst)
	return encoded
}

func Prob3() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed, n := lib.HexDecode([]byte(message))
	unhexed_ := unhexed[:n]
	_, guess := lib.DecryptSingleByteXOR(unhexed_)
	fmt.Println(string(guess))
}

func Prob4() {
	guess := prob4()
	fmt.Println(string(guess))
}

func prob4() []byte {
	content := lib.OpenFile("04")
	max := 0.0
	var best_guess []byte

	for _, line := range content {
		unhexed, n := lib.HexDecode(line)
		for suspect := 32; suspect < 128; suspect++ {
			dst := make([]byte, n)
			lib.XORByte(dst, unhexed[:n], byte(suspect))
			rating := lib.CalcRating(dst)
			if rating > max {
				max = rating
				best_guess = dst
			}
		}
	}
	return bytes.TrimRight(best_guess, "\n")
}

func Prob5() {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	encodedStr := prob5(message, key)
	fmt.Println(encodedStr)
}

func prob5(message, key string) string {
	xored := make([]byte, len(message))
	lib.XORBytes(xored, []byte(message), []byte(key))
	return hex.EncodeToString(xored)
}

func prob6() (string, string) {
	content := string(bytes.Join(lib.OpenFile("06"), []byte("")))
	data, _ := base64.StdEncoding.DecodeString(content)
	keysize := lib.FindKeySize(data)

	blocks := [][]byte{}
	for i := 0; float64(i) < math.Ceil(float64(len(data))/float64(keysize)); i++ {
		upper_limit := int(math.Min(float64((i+1)*keysize), float64(len(data))))
		blocks = append(blocks, data[i*keysize:upper_limit])
	}
	transposed := lib.Transpose(blocks, keysize)

	var encryption_key string
	for i := range transposed {
		guess, _ := lib.DecryptSingleByteXOR(transposed[i])
		encryption_key += string(guess)
	}
	plain_text := make([]byte, len(data))
	lib.XORBytes(plain_text, []byte(data), []byte(encryption_key))
	return encryption_key, string(plain_text)
}

func Prob6() {
	encryption_key, _ := prob6()
	fmt.Println(encryption_key)
}

func prob7(key []byte, block_size int) string {
	content := string(bytes.Join(lib.OpenFile("07"), []byte("")))
	cipherText, _ := base64.StdEncoding.DecodeString(content)
	decrypted := lib.DecryptECB(cipherText, key, block_size)
	return string(decrypted)
}

func Prob7() {
	decrypted := prob7([]byte("YELLOW SUBMARINE"), 16)
	fmt.Println(string(decrypted))
}

func prob8() string {
	lines := lib.OpenFile("08")
	var result string
	for _, line := range lines {
		data, _ := lib.HexDecode(line)
		if lib.DetectECB(data) {
			result = string(line)
		}
	}
	return result
}

func Prob8() {
	fmt.Println(prob8())
}

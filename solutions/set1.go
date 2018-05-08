package solutions

import "bytes"
import "encoding/base64"
import "encoding/hex"
import "fmt"
import "math"

func Prob1() {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	encoded := HexToBase64([]byte(hex_string))
	fmt.Println(encoded)
}

func Prob2() {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	encodedStr := prob2([]byte(msg1), []byte(msg2))
	fmt.Println(encodedStr)
}

func prob2(msg1, msg2 []byte) string {
	bin1 := make([]byte, hex.DecodedLen(len(msg1)))
	bin2 := make([]byte, hex.DecodedLen(len(msg2)))
	hex.Decode(bin1, msg1)
	hex.Decode(bin2, msg2)
	fmt.Println(bin1)
	fmt.Println(bin2)

	dst := make([]byte, len(bin1))
	XORBytes(dst, bin1, bin2)
	encodedStr := hex.EncodeToString(dst)
	return encodedStr
}

func Prob3() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed := make([]byte, hex.DecodedLen(len(message)))
	n, _ := hex.Decode(unhexed, []byte(message))
	unhexed_ := unhexed[:n]
	_, guess := DecryptSingleByteXOR(unhexed_)
	fmt.Println(string(guess))
}

func Prob4() {
	guess := prob4()
	fmt.Println(string(guess))
}

func prob4() []byte {
	content := OpenFile("04")
	max := 0.0
	var best_guess []byte

	for _, line := range content {
		unhexed := make([]byte, hex.DecodedLen(len(line)))
		n, _ := hex.Decode(unhexed, line)
		for suspect := 32; suspect < 128; suspect++ {
			dst := make([]byte, n)
			XORByte(dst, unhexed[:n], byte(suspect))
			rating := CalcRating(dst)
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
	XORBytes(xored, []byte(message), []byte(key))
	return hex.EncodeToString(xored)
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
	content := string(bytes.Join(OpenFile("06"), []byte("")))
	data, _ := base64.StdEncoding.DecodeString(content)
	keysize := FindKeySize(data)

	blocks := [][]byte{}
	for i := 0; float64(i) < math.Ceil(float64(len(data))/float64(keysize)); i++ {
		upper_limit := int(math.Min(float64((i+1)*keysize), float64(len(data))))
		blocks = append(blocks, data[i*keysize:upper_limit])
	}
	transposed := transpose(blocks, keysize)

	var encryption_key string
	for i := range transposed {
		guess, _ := DecryptSingleByteXOR(transposed[i])
		encryption_key += string(guess)
	}
	plain_text := make([]byte, len(data))
	XORBytes(plain_text, []byte(data), []byte(encryption_key))
	return encryption_key, string(plain_text)
}

func Prob6() {
	encryption_key, _ := prob6()
	fmt.Println(encryption_key)
}

func prob7(key []byte, block_size int) string {
	content := string(bytes.Join(OpenFile("07"), []byte("")))
	cipherText, _ := base64.StdEncoding.DecodeString(content)
	decrypted := DecryptECB(cipherText, key, block_size)
	return string(decrypted)
}

func Prob7() {
	decrypted := prob7([]byte("YELLOW SUBMARINE"), 16)
	fmt.Println(string(decrypted))
}

func prob8() string {
	lines := OpenFile("08")
	var result string
	for _, line := range lines {
		if DetectECB(string(line)) {
			result = string(line)
		}
	}
	return result
}

func Prob8() {
	fmt.Println(prob8())
}

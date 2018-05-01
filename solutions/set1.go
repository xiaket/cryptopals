package solutions

import "encoding/hex"
import "fmt"
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
	guess := prob3(message)
	fmt.Println(guess)
}

func prob3(message string) string {
	unhexed, _ := hex.DecodeString(message)

	dst := make([]byte, len(unhexed))
	max := 1.0
	best_guess := ""
	for suspect := 32; suspect < 128; suspect++ {
		cryptopals.XORByte(dst, unhexed, byte(suspect))
		decoded := string(dst)
		rating := cryptopals.CalcRating(decoded)
		if rating > max {
			best_guess = decoded
			max = rating
		}
	}
	return best_guess
}

func Prob4() {
	guess := prob4()
	fmt.Println(guess)
}

func prob4() string {
	content := cryptopals.OpenFile("04")
	max := 1.0
	best_guess := ""

	for _, line := range content {
		unhexed, _ := hex.DecodeString(line)
		dst := make([]byte, len(unhexed))
		for suspect := 32; suspect < 128; suspect++ {
			cryptopals.XORByte(dst, unhexed, byte(suspect))
			decoded := string(dst)
			rating := cryptopals.CalcRating(decoded)
			if rating > max {
				max = rating
				best_guess = decoded
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

func Prob6() {
	content := strings.Join(cryptopals.OpenFile("06"), "")
	fmt.Println(content)
}

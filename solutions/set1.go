package solutions

import "bufio"
import "encoding/hex"
import "encoding/base64"
import "fmt"
import "log"
import "os"
import "../lib"

func Prob1(hex_string string) string {
	src := []byte(hex_string)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(dst)
	return encoded
}

func Prob2() {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	bin1 := to_bin(msg1)
	bin2 := to_bin(msg2)
	dst := make([]byte, len(bin1))
	cryptopals.SafeXORBytes(dst, bin1, bin2)
	encodedStr := hex.EncodeToString(dst)
	fmt.Println(encodedStr)
}

func to_bin(msg string) []byte {
	src := []byte(msg)
	bin := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(bin, src)
	return bin
}

func Prob3() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed, _ := hex.DecodeString(message)

	dst := make([]byte, len(unhexed))
	for suspect := 32; suspect < 128; suspect++ {
		cryptopals.SafeXORByte(dst, unhexed, byte(suspect))
		decoded := string(dst)
		rating := cryptopals.CalcRating(decoded)
		if rating > 1.0 {
			fmt.Println(suspect, dst, rating, decoded)
		}
	}
	// hand picked result: cOOKINGmcSLIKEAPOUNDOFBACON
}

func Prob4() {
	inFile, _ := os.Open("file.04.txt")
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	max := 1.0

	for scanner.Scan() {
		line := scanner.Text()
		unhexed, _ := hex.DecodeString(line)
		dst := make([]byte, len(unhexed))
		for suspect := 32; suspect < 128; suspect++ {
			cryptopals.SafeXORByte(dst, unhexed, byte(suspect))
			decoded := string(dst)
			rating := cryptopals.CalcRating(decoded)
			if rating > max {
				max = rating
				fmt.Println(rating, suspect, decoded)
			}
		}
	}
}

func Prob5() {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	xored := make([]byte, len(message))
	cryptopals.SafeXORBytes(xored, []byte(message), []byte(key))
	encodedStr := hex.EncodeToString(xored)
	fmt.Println(encodedStr)
}

func Prob6() {
	const message1 = "this is a test"
	const message2 = "wokka wokka!!!"
	hamming_distance := cryptopals.HammingDistance(message1, message2)
	fmt.Println(hamming_distance)
}

package solutions

import "bufio"
import "encoding/hex"
import "fmt"
import "os"
import "path/filepath"
import "../lib"

func Prob1() {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	encoded := cryptopals.HexToBase64(hex_string)
	fmt.Println(encoded)
}

func Prob2() {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	bin1 := cryptopals.DecodeHex(msg1)
	bin2 := cryptopals.DecodeHex(msg2)
	fmt.Println(bin1)
	fmt.Println(bin2)

	dst := make([]byte, len(bin1))
	cryptopals.SafeXORBytes(dst, bin1, bin2)
	encodedStr := hex.EncodeToString(dst)
	fmt.Println(encodedStr)
}

func Prob3() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed, _ := hex.DecodeString(message)

	dst := make([]byte, len(unhexed))
	max := 1.0
	best_guess := ""
	for suspect := 32; suspect < 128; suspect++ {
		cryptopals.SafeXORByte(dst, unhexed, byte(suspect))
		decoded := string(dst)
		rating := cryptopals.CalcRating(decoded)
		if rating > max {
			best_guess = decoded
			max = rating
		}
	}
	fmt.Println(best_guess)
}

func Prob4() {
	_, git_root := cryptopals.GitRootDir()
	inFile, _ := os.Open(filepath.Join(git_root, "solutions", "file.04.txt"))
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	max := 1.0
	best_guess := ""

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
				best_guess = decoded
			}
		}
	}
	fmt.Println(best_guess)
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

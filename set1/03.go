package main

import "encoding/hex"
import "fmt"
import "../lib"

func main() {
	const message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	unhexed, _ := hex.DecodeString(message)

	dst := make([]byte, len(unhexed))
	for suspect := 32; suspect < 128; suspect++ {
		cryptopals.SafeXORBytes(dst, unhexed, byte(suspect))
		decoded := string(dst)
		rating := cryptopals.CalcRating(decoded)
		if rating > 1.0 {
			fmt.Println(suspect, dst, rating, decoded)
		}
	}
	// hand picked result: cOOKINGmcSLIKEAPOUNDOFBACON
}

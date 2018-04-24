package main

import "encoding/hex"
import "fmt"
import "../lib"

func main() {
	const message = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
	const key = "ICE"
	xored := make([]byte, len(message))
	cryptopals.SafeXORBytes(xored, []byte(message), []byte(key))
	encodedStr := hex.EncodeToString(xored)
	fmt.Println(encodedStr)
}

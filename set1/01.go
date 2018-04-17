package main

import "encoding/hex"
import "encoding/base64"
import "fmt"
import "log"

func main() {
	const hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	src := []byte(hex_string)
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		log.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(dst)
	fmt.Println(encoded)
}

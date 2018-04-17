package main

import "encoding/hex"
import "fmt"

func main() {
	const msg1 = "1c0111001f010100061a024b53535009181c"
	const msg2 = "686974207468652062756c6c277320657965"
	bin1 := to_bin(msg1)
	bin2 := to_bin(msg2)
	dst := make([]byte, len(bin1))
	safeXORBytes(dst, bin1, bin2)
	encodedStr := hex.EncodeToString(dst)
	fmt.Println(encodedStr)
}

func to_bin(msg string) []byte {
	src := []byte(msg)
	bin := make([]byte, hex.DecodedLen(len(src)))
	hex.Decode(bin, src)
	return bin
}

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

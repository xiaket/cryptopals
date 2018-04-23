package main

import "bufio"
import "encoding/hex"
import "fmt"
import "os"
import "../lib"

func main() {
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
			cryptopals.SafeXORBytes(dst, unhexed, byte(suspect))
			decoded := string(dst)
			rating := cryptopals.CalcRating(decoded)
			if rating > max {
				max = rating
				fmt.Println(rating, suspect, decoded)
			}
		}
	}
}

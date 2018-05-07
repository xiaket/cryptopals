package solutions

import "fmt"

func Prob9() {
	const message = "YELLOW SUBMARINE"
	padded := PKCS7Padding([]byte(message), 20)
	fmt.Println(padded)
}

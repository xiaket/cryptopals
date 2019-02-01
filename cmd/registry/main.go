package main

import (
	"github.com/xiaket/cryptopals/pkg/set1"
	"github.com/xiaket/cryptopals/pkg/set2"
	"os"
)

func main() {
	registry := map[string]func(){
		"1":  set1.Prob1,
		"2":  set1.Prob2,
		"3":  set1.Prob3,
		"4":  set1.Prob4,
		"5":  set1.Prob5,
		"6":  set1.Prob6,
		"7":  set1.Prob7,
		"8":  set1.Prob8,
		"9":  set2.Prob9,
		"10": set2.Prob10,
		"11": set2.Prob11,
	}
	registry[os.Args[1]]()
}

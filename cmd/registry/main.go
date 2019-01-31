package main

import (
	"github.com/xiaket/cryptopals/pkg/set1"
	"os"
)

func main() {
	registry := map[string]func(){
		"1": set1.Prob1,
		"2": set1.Prob2,
		"3": set1.Prob3,
		"4": set1.Prob4,
		"5": set1.Prob5,
		"6": set1.Prob6,
		"7": set1.Prob7,
		"8": set1.Prob8,
	}
	registry[os.Args[1]]()
}

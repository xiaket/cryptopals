package main

import "fmt"
import "os"
import "strconv"
import "./solutions"
import "./lib"

func main() {
	target := os.Args[1]
	problem, err := strconv.ParseInt(target, 10, 8)
	if err != nil {
		if target == "test" {
			problem = 0
		} else {
			panic(fmt.Sprintf("Unknown target: " + target))
		}
	}
	cryptopals.Call(solutions.Registry, problem)
}

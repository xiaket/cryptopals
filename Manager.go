package main

import "fmt"
import "os"
import "strconv"
import "./solutions"

func main() {
	target := os.Args[1]
	problem, err := strconv.ParseInt(target, 10, 8)
	if err != nil {
		switch target {
		case "test":
			problem = 0
		case "all":
			problem = -1
		default:
			panic(fmt.Sprintf("Unknown target: " + target))
		}
	}
	solutions.Registry[problem]()
}

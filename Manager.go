package main

import "os"
import "./solutions"

func main() {
	solutions.Registry[os.Args[1]]()
}

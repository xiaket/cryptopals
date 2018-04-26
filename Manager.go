package main

import "os"
import "./solutions"

func main() {
	solutions.Registry.Call(os.Args[1])
}

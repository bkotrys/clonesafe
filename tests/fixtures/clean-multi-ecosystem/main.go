package main

//go:generate go run ./internal/codegen
//go:generate stringer -type=Status

import "fmt"

func main() {
	fmt.Println("hello")
}

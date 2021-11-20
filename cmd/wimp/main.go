package main

import (
	_ "net/http/pprof"

	cmd2 "github.com/onepeerlabs/wimp/cmd/wimp/cmd"
)

func main() {
	cmd2.Execute()
}
package main

import (
	"fmt"
	"os"

	"github.com/dhcgn/jpghash"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <jpeg-file>\n", os.Args[0])
		os.Exit(2)
	}
	sum, err := jpghash.HashFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(sum)
}

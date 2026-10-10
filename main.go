package main

import (
	"flag"
	"fmt"
	"os"

	"rzwinkels/elf_scanner/utils"
)

func main() {
	inputPath := flag.String("path", "", "path to file or directory")

	utils.PrintBanner()
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: elf_scanner -path ./pad/naar/bestand-of-map")
		os.Exit(2)
	}

	fmt.Printf("Recieved path: %s\n", *inputPath)
}

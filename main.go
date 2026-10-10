package main

import (
	"flag"
	"fmt"
	"os"

	"rzwinkels/elf_scanner/utils"
)

func main() {
	inputPath := flag.String("path", "", "path to a file or directory")

	utils.PrintBanner()
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: elf_scanner -path ./path/to/file-or-directory")
		os.Exit(2)
	}

	binaries, err := CollectELFBinaries(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read path: %v\n", err)
		os.Exit(1)
	}

	for _, binary := range binaries {
		fmt.Printf("%+v\n", binary)
	}
}

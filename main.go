package main

import (
	"flag"
	"fmt"
	"os"

	"rzwinkels/elf_scanner/heuristics"
	"rzwinkels/elf_scanner/logger"
	"rzwinkels/elf_scanner/utils"
)

func main() {
	inputPath := flag.String("path", "", "path to a file or directory")
	logLevel := flag.String("log-level", "info", "minimum log level: info, warning, or critical")

	flag.Parse()

	level, err := logger.ParseLevel(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	log := logger.New(os.Stderr, level)
	utils.PrintBanner(log)

	if *inputPath == "" {
		log.Critical("missing required -path flag")
		fmt.Fprintln(os.Stderr, "usage: elf_scanner -path ./path/to/file-or-directory")
		os.Exit(2)
	}

	log.Info("scanning %s", *inputPath)
	binaries, err := CollectELFBinaries(*inputPath)
	if err != nil {
		log.Critical("failed to read path: %v", err)
		os.Exit(1)
	}
	log.Info("found %d ELF binaries", len(binaries))

	for _, binary := range binaries {
		binary.Print(log)

		results, err := heuristics.EvaluateELFHeuristics(binary)
		if err != nil {
			log.Warning("failed to evaluate heuristics for %s: %v", binary.Path, err)
			continue
		}
		results.Print(log)

		log.Println()
	}
}

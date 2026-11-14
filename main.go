package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"rzwinkels/elf_scanner/heuristics"
	"rzwinkels/elf_scanner/logger"
	"rzwinkels/elf_scanner/scoring"
	"rzwinkels/elf_scanner/utils"
)

func main() {
	startTime := time.Now()
	inputPath := flag.String("path", "", "path to a file or directory")
	logLevel := flag.String("log-level", "info", "minimum log level: info, warning, or critical")
	scoringConfigPath := flag.String("scoring-config", "scoring/config.json", "path to the scoring JSON configuration")

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
		log.Critical("usage: elf_scanner -path ./path/to/file-or-directory")
		os.Exit(2)
	}

	scoringConfig, err := scoring.LoadConfig(*scoringConfigPath)
	if err != nil {
		log.Critical("failed to load scoring config: %v", err)
		os.Exit(1)
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

		score, err := scoring.Score(results, scoringConfig)
		if err != nil {
			log.Critical("failed to score heuristics for %s: %v", binary.Path, err)
			continue
		}
		log.Warning("Final score for %s: %.2f/%.2f", score.Name, score.Score, score.MaxScore)

		log.Println()
	}

	duration := time.Since(startTime)
	log.Info("Scanned %d ELFs in %s", len(binaries), duration)
	if len(binaries) > 0 {
		log.Info("Average time per ELF: %s", duration/time.Duration(len(binaries)))
	}
}

package heuristics

import (
	"debug/elf"
	"fmt"
	"io"
	"math"
	"os"

	"rzwinkels/elf_scanner/structs"
)

const (
	highEntropyThreshold = 7.5
	minEntropySectionSize = 4096
)

// applyHighEntropyHeuristic meet zelf de ruwe section-bytes; de ELF struct blijft metadata.
func applyHighEntropyHeuristic(binary structs.ELFBinary, results *structs.ELFHeuristicResults) error {
	file, err := os.Open(binary.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return err
	}
	defer elfFile.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := uint64(info.Size())

	for i := range results.Heuristics {
		heuristic := &results.Heuristics[i]
		if heuristic.ID != structs.HeuristicHighEntropy {
			continue
		}

		for _, section := range elfFile.Sections {
			if section.Size < minEntropySectionSize || section.Type == elf.SHT_NOBITS || section.Type == elf.SHT_NULL {
				continue
			}
			if section.Offset > fileSize || section.Size > fileSize-section.Offset {
				return fmt.Errorf("section %q lies outside the file", section.Name)
			}

			entropy, err := shannonEntropy(io.NewSectionReader(file, int64(section.Offset), int64(section.Size)))
			if err != nil {
				return fmt.Errorf("section %q: %w", section.Name, err)
			}

			executable := section.Flags&elf.SHF_EXECINSTR != 0
			heuristic.Evaluated = true
			heuristic.Evidence = append(heuristic.Evidence,
				fmt.Sprintf("section %q: entropy=%.3f bits/byte, size=%d bytes, executable=%t",
					section.Name, entropy, section.Size, executable))
			if entropy > heuristic.Score {
				heuristic.Score = entropy
			}
			if entropy >= highEntropyThreshold {
				heuristic.Triggered = true
			}
		}
		return nil
	}
	return nil
}

// shannonEntropy berekent bits per byte zonder de volledige section in geheugen te laden.
func shannonEntropy(reader io.Reader) (float64, error) {
	var counts [256]uint64
	var total uint64
	buffer := make([]byte, 32*1024)

	for {
		n, err := reader.Read(buffer)
		for _, value := range buffer[:n] {
			counts[value]++
		}
		total += uint64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if total == 0 {
		return 0, nil
	}

	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy, nil
}

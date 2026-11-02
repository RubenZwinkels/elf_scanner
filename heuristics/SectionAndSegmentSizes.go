package heuristics

import (
	"fmt"

	"rzwinkels/elf_scanner/structs"
)

// applySectionAndSegmentSizes meet groottes zonder al een afwijkingsgrens te kiezen.
func applySectionAndSegmentSizes(binary structs.ELFBinary, results *structs.ELFHeuristicResults) {
	for i := range results.Heuristics {
		heuristic := &results.Heuristics[i]
		if heuristic.ID != structs.HeuristicUnusualSectionSize {
			continue
		}

		var largest uint64
		for index, section := range binary.Sections {
			if section.Type == "SHT_NULL" {
				continue
			}
			if section.Type == "SHT_NOBITS" {
				heuristic.Evidence = append(heuristic.Evidence,
					fmt.Sprintf("section %d %q: NOBITS, memory size=%d bytes, no file bytes",
						index, section.Name, section.Size))
				continue
			}
			heuristic.Evidence = append(heuristic.Evidence,
				fmt.Sprintf("section %d %q: file size=%d bytes", index, section.Name, section.Size))
			if section.Size > largest {
				largest = section.Size
			}
		}

		for index, segment := range binary.Segments {
			heuristic.Evidence = append(heuristic.Evidence,
				fmt.Sprintf("segment %d (%s): file size=%d bytes, memory size=%d bytes",
					index, segment.Type, segment.FileSize, segment.MemorySize))
			if segment.FileSize > largest {
				largest = segment.FileSize
			}
		}

		heuristic.Score = float64(largest)
		heuristic.Unit = "bytes (largest on-disk section or segment)"
		heuristic.Evaluated = true
		return
	}
}

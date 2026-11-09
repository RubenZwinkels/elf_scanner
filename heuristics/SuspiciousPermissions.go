package heuristics

import (
	"fmt"
	"strings"

	"rzwinkels/elf_scanner/structs"
)

// applySuspiciousPermissions controleert rechten van sections die in geheugen worden geladen
// en van laadbare segmenten. Value is het aantal meldingen, geen gewogen score.
func applySuspiciousPermissions(binary structs.ELFBinary, results *structs.ELFHeuristicResults) {
	for i := range results.Heuristics {
		heuristic := &results.Heuristics[i]
		if heuristic.ID != structs.HeuristicSuspiciousPermissions {
			continue
		}

		var checkedSections, checkedSegments, findings int
		for index, section := range binary.Sections {
			if !hasELFFlag(section.Flags, "SHF_ALLOC") {
				continue
			}
			checkedSections++
			if hasELFFlag(section.Flags, "SHF_WRITE") && hasELFFlag(section.Flags, "SHF_EXECINSTR") {
				findings++
				heuristic.Evidence = append(heuristic.Evidence,
					fmt.Sprintf("section %d %q: writable and executable (flags=%s)", index, section.Name, section.Flags))
			}
		}

		for index, segment := range binary.Segments {
			if segment.Type != "PT_LOAD" {
				continue
			}
			checkedSegments++
			if hasELFFlag(segment.Flags, "PF_W") && hasELFFlag(segment.Flags, "PF_X") {
				findings++
				heuristic.Evidence = append(heuristic.Evidence,
					fmt.Sprintf("segment %d (PT_LOAD): writable and executable (flags=%s)", index, segment.Flags))
			}
		}

		heuristic.Value = float64(findings)
		heuristic.Unit = "writable/executable sections and loadable segments"
		heuristic.Evaluated = true
		heuristic.Triggered = findings > 0
		heuristic.Evidence = append([]string{
			fmt.Sprintf("Checked %d allocated sections and %d loadable segments; sections may overlap segments, so findings are not distinct memory regions.", checkedSections, checkedSegments),
		}, heuristic.Evidence...)
		return
	}
}

// debug/elf geeft de vlaggen als namen gescheiden door '+' terug.
func hasELFFlag(flags, name string) bool {
	for _, flag := range strings.Split(flags, "+") {
		if strings.TrimSpace(flag) == name {
			return true
		}
	}
	return false
}

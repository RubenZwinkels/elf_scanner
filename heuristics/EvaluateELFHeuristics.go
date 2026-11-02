package heuristics


import "rzwinkels/elf_scanner/structs"

// EvaluateELFHeuristics verzamelt de ruwe resultaten van alle geïmplementeerde heuristieken.
func EvaluateELFHeuristics(binary structs.ELFBinary) (structs.ELFHeuristicResults, error) {
	results := newELFHeuristicResults(binary)
	applyDirectMeasurements(binary, &results)

	if err := applyHighEntropyHeuristic(binary, &results); err != nil {
		return results, err
	}
	return results, nil
}

// applyDirectMeasurements neemt bestaande ELF-properties over.
func applyDirectMeasurements(binary structs.ELFBinary, results *structs.ELFHeuristicResults) {
	for i := range results.Heuristics {
		heuristic := &results.Heuristics[i]
		switch heuristic.ID {
		case structs.HeuristicFewImports:
			heuristic.Score = float64(len(binary.ImportedSymbols))
			heuristic.Unit = "imported symbols"
			heuristic.Evaluated = true
			heuristic.Evidence = []string{"Raw import count; no suspiciousness threshold applied."}
		case structs.HeuristicUnusualSectionCount:
			heuristic.Score = float64(binary.SectionCount)
			heuristic.Unit = "sections"
			heuristic.Evaluated = true
			heuristic.Evidence = []string{"Raw section count; no architecture-specific baseline applied."}
		case structs.HeuristicStrippedSymbols:
			if binary.IsStripped {
				heuristic.Score = 1
			}
			heuristic.Unit = "boolean (1=stripped)"
			heuristic.Evaluated = true
			heuristic.Triggered = binary.IsStripped
			heuristic.Evidence = []string{"Stripped status copied from ELF metadata."}
		}
	}
}

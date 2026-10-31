package heuristics


import "rzwinkels/elf_scanner/structs"

// EvaluateELFHeuristics verzamelt de ruwe resultaten van alle geïmplementeerde heuristieken.
func EvaluateELFHeuristics(binary structs.ELFBinary) (structs.ELFHeuristicResults, error) {
	results := newELFHeuristicResults(binary)
	if err := applyHighEntropyHeuristic(binary, &results); err != nil {
		return results, err
	}
	return results, nil
}

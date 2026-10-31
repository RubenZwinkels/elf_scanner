package heuristics

import "rzwinkels/elf_scanner/structs"

// newELFHeuristicResults maakt een container voor de ongewogen resultaten.
func newELFHeuristicResults(binary structs.ELFBinary) structs.ELFHeuristicResults {
	return structs.ELFHeuristicResults{
		FileSHA256: binary.SHA256,
		Path:       binary.Path,
		Name:       binary.Name,
		Heuristics: defaultHeuristics(),
	}
}

// defaultHeuristics registreert de heuristieken; ontbrekende evaluaties blijven zichtbaar.
func defaultHeuristics() []structs.ELFHeuristicScore {
	return []structs.ELFHeuristicScore{
		{ID: structs.HeuristicHighEntropy, Name: "High section entropy", Unit: "bits/byte"},
		{ID: structs.HeuristicFewImports, Name: "Zero or very few imported functions"},
		{ID: structs.HeuristicUnusualSectionCount, Name: "Unusual number of sections"},
		{ID: structs.HeuristicUnusualSectionSize, Name: "Unusual section or segment size"},
		{ID: structs.HeuristicSuspiciousPermissions, Name: "Suspicious section or segment permissions"},
		{ID: structs.HeuristicStrippedSymbols, Name: "Stripped symbols"},
		{ID: structs.HeuristicMalformedHeader, Name: "Missing or manipulated ELF header information"},
		{ID: structs.HeuristicArchitectureOutlier, Name: "Architecture-specific outlier behavior"},
		{ID: structs.HeuristicSuspiciousStrings, Name: "Suspicious dynamic strings"},
		{ID: structs.HeuristicSuspiciousSyscalls, Name: "Suspicious statically identified syscalls"},
	}
}

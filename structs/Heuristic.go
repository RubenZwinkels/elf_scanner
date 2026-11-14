package structs

import "rzwinkels/elf_scanner/logger"

// HeuristicID is een vaste identifier voor een malware-heuristiek.
type HeuristicID string

const (
	HeuristicHighEntropy           HeuristicID = "high_entropy"
	HeuristicFewImports            HeuristicID = "few_imports"
	HeuristicUnusualSectionCount   HeuristicID = "unusual_section_count"
	HeuristicUnusualSectionSize    HeuristicID = "unusual_section_size"
	HeuristicSuspiciousPermissions HeuristicID = "suspicious_permissions"
	HeuristicStrippedSymbols       HeuristicID = "stripped_symbols"
	HeuristicMalformedHeader       HeuristicID = "malformed_header"
	HeuristicArchitectureOutlier   HeuristicID = "architecture_outlier"
	HeuristicSuspiciousStrings     HeuristicID = "suspicious_strings"
	HeuristicSuspiciousSyscalls    HeuristicID = "suspicious_syscalls"
)

// ELFHeuristicResults verzamelt ongewogen metingen voor één ELF-bestand.
type ELFHeuristicResults struct {
	FileSHA256 string
	Path       string
	Name       string
	Heuristics []ELFHeuristicScore
}

// ELFHeuristicScore bevat de ruwe score van één heuristiek, zonder gewicht.
type ELFHeuristicScore struct {
	ID        HeuristicID
	Name      string
	Value     float64
	Unit      string
	Evaluated bool
	Triggered bool
	Evidence  []string
}

// Print toont alle heuristieken zonder totaalscore of classificatie.
func (results ELFHeuristicResults) Print(log *logger.Logger) {
	log.Println("  Heuristic results:")
	log.Printf("    File: %s\n", results.Name)
	log.Printf("    SHA256: %s\n", results.FileSHA256)
	for _, heuristic := range results.Heuristics {
		heuristic.Print(log)
	}
}

// Print toont de ruwe score en onderbouwing van één heuristiek.
func (heuristic ELFHeuristicScore) Print(log *logger.Logger) {
	if !heuristic.Evaluated {
		log.Printf("    - [%s] %s: not evaluated\n", heuristic.ID, heuristic.Name)
		return
	}
	log.Printf("    - [%s] %s: %.3f %s (triggered=%t)\n",
		heuristic.ID, heuristic.Name, heuristic.Value, heuristic.Unit, heuristic.Triggered)
	for _, evidence := range heuristic.Evidence {
		log.Printf("        evidence: %s\n", evidence)
	}
}

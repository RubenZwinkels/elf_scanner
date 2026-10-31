package structs

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

// ELFScore houdt alle heuristiek-scores bij voor één ELF-bestand.
type ELFScore struct {
	FileSHA256 string
	Path       string
	Name       string

	Heuristics []ELFHeuristicScore
}

// ELFHeuristicScore houdt de score en onderbouwing van één heuristiek bij.
type ELFHeuristicScore struct {
	ID          HeuristicID
	Name        string
	Reliability string
	// MaxScore is de maximale score die deze heuristiek kan bijdragen.
	MaxScore int
	// Score is de daadwerkelijk toegekende score voor deze heuristiek.
	Score int
}

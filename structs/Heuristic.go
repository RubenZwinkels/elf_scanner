package structs

import "fmt"
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

	// Triggered geeft aan of deze heuristiek iets verdachts heeft gevonden.
	Triggered bool

	// Evidence bevat korte redenen of gemeten waarden, bijvoorbeeld:
	// "section .text entropy=7.91" of "import count=0".
	Evidence []string
}

// NewELFScore maakt een lege score-container met alle bekende heuristieken.
// De echte score-logica wordt later per heuristiek ingevuld.
func NewELFScore(binary ELFBinary) ELFScore {
	return ELFScore{
		FileSHA256: binary.SHA256,
		Path:       binary.Path,
		Name:       binary.Name,
		Heuristics: DefaultHeuristics(),
	}
}

// DefaultHeuristics geeft alle heuristieken terug met hun vaste metadata en max scores.
func DefaultHeuristics() []ELFHeuristicScore {
	return []ELFHeuristicScore{
		{
			ID:          HeuristicHighEntropy,
			Name:        "High section or segment entropy",
			Reliability: "Medium",
			MaxScore:    4,
		},
		{
			ID:          HeuristicFewImports,
			Name:        "Zero or very few imported functions",
			Reliability: "Medium-high",
			MaxScore:    6,
		},
		{
			ID:          HeuristicUnusualSectionCount,
			Name:        "Unusual number of sections",
			Reliability: "Low-medium",
			MaxScore:    3,
		},
		{
			ID:          HeuristicUnusualSectionSize,
			Name:        "Unusual section or segment size",
			Reliability: "Medium",
			MaxScore:    4,
		},
		{
			ID:          HeuristicSuspiciousPermissions,
			Name:        "Suspicious section or segment permissions",
			Reliability: "Medium-high",
			MaxScore:    6,
		},
		{
			ID:          HeuristicStrippedSymbols,
			Name:        "Stripped symbols",
			Reliability: "Low",
			MaxScore:    2,
		},
		{
			ID:          HeuristicMalformedHeader,
			Name:        "Missing or manipulated ELF header information",
			Reliability: "High",
			MaxScore:    7,
		},
		{
			ID:          HeuristicArchitectureOutlier,
			Name:        "Architecture-specific outlier behavior",
			Reliability: "Medium",
			MaxScore:    5,
		},
		{
			ID:          HeuristicSuspiciousStrings,
			Name:        "Suspicious dynamic strings",
			Reliability: "Medium",
			MaxScore:    4,
		},
		{
			ID:          HeuristicSuspiciousSyscalls,
			Name:        "Suspicious statically identified syscalls",
			Reliability: "Medium-high",
			MaxScore:    6,
		},
	}
}

// TotalScore telt de toegekende punten van alle heuristieken op.
func (score ELFScore) TotalScore() int {
	total := 0
	for _, heuristic := range score.Heuristics {
		total += heuristic.Score
	}

	return total
}

// MaxScore telt de maximale mogelijke punten van alle heuristieken op.
func (score ELFScore) MaxScore() int {
	total := 0
	for _, heuristic := range score.Heuristics {
		total += heuristic.MaxScore
	}

	return total
}

// Print toont de heuristic score op een observeerbare manier.
func (score ELFScore) Print() {
	fmt.Println("  Heuristic scores:")
	fmt.Printf("    File: %s\n", score.Name)
	fmt.Printf("    SHA256: %s\n", score.FileSHA256)
	fmt.Printf("    Total score: %d/%d\n", score.TotalScore(), score.MaxScore())

	for _, heuristic := range score.Heuristics {
		heuristic.Print()
	}
}

// Print toont één heuristiek inclusief score en evidence.
func (heuristic ELFHeuristicScore) Print() {
	status := "not triggered"
	if heuristic.Triggered {
		status = "triggered"
	}

	fmt.Printf("    - [%s] %s: %d/%d (%s, reliability=%s)\n",
		heuristic.ID,
		heuristic.Name,
		heuristic.Score,
		heuristic.MaxScore,
		status,
		heuristic.Reliability,
	)

	for _, evidence := range heuristic.Evidence {
		fmt.Printf("        evidence: %s\n", evidence)
	}
}

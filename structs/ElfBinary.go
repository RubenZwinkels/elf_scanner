package structs

import "fmt"

// ELFBinary houdt de verzamelde info bij van één ELF-bestand.
type ELFBinary struct {
	Path string
	Name string
	Size int64

	FileMode   string
	ModifiedAt string

	Class        string
	Endianness   string
	Version      string
	OSABI        string
	ABIVersion   uint8
	Type         string
	Architecture string
	EntryPoint   uint64

	SectionCount int
	SegmentCount int

	IsStripped bool

	ImportedLibraries []string
	ImportedSymbols   []ELFImportedSymbol
	Symbols           []ELFSymbol
	DynamicSymbols    []ELFSymbol

	Sections []ELFSection
	Segments []ELFSegment
}

// ELFSection houdt ELF section-header info bij.
type ELFSection struct {
	Name      string
	Type      string
	Flags     string
	Address   uint64
	Offset    uint64
	Size      uint64
	Link      uint32
	Info      uint32
	Alignment uint64
	EntrySize uint64
}

// ELFSegment houdt ELF program-header info bij.
type ELFSegment struct {
	Type            string
	Flags           string
	Offset          uint64
	VirtualAddress  uint64
	PhysicalAddress uint64
	FileSize        uint64
	MemorySize      uint64
	Alignment       uint64
}

// ELFImportedSymbol houdt dynamic import info bij.
type ELFImportedSymbol struct {
	Name    string
	Version string
	Library string
}

// ELFSymbol houdt symbol-table info bij.
type ELFSymbol struct {
	Name    string
	Info    byte
	Other   byte
	Section string
	Value   uint64
	Size    uint64
	Version string
	Library string
}

// Print toont één ELF-bestand op een leesbare manier.
func (binary ELFBinary) Print() {
	fmt.Print("===================================================================================")
	fmt.Printf("File: %s\n", binary.Name)
	fmt.Printf("  Path: %s\n", binary.Path)
	fmt.Printf("  Size: %d bytes\n", binary.Size)
	fmt.Printf("  Mode: %s\n", binary.FileMode)
	fmt.Printf("  Modified: %s\n", binary.ModifiedAt)

	fmt.Println("  ELF header:")
	fmt.Printf("    Class: %s\n", binary.Class)
	fmt.Printf("    Endianness: %s\n", binary.Endianness)
	fmt.Printf("    Version: %s\n", binary.Version)
	fmt.Printf("    OS ABI: %s\n", binary.OSABI)
	fmt.Printf("    ABI version: %d\n", binary.ABIVersion)
	fmt.Printf("    Type: %s\n", binary.Type)
	fmt.Printf("    Architecture: %s\n", binary.Architecture)
	fmt.Printf("    Entry point: 0x%x\n", binary.EntryPoint)
	fmt.Printf("    Stripped: %t\n", binary.IsStripped)

	fmt.Println("  Counts:")
	fmt.Printf("    Sections: %d\n", binary.SectionCount)
	fmt.Printf("    Segments: %d\n", binary.SegmentCount)
	fmt.Printf("    Imported libraries: %d\n", len(binary.ImportedLibraries))
	fmt.Printf("    Imported symbols: %d\n", len(binary.ImportedSymbols))
	fmt.Printf("    Symbols: %d\n", len(binary.Symbols))
	fmt.Printf("    Dynamic symbols: %d\n", len(binary.DynamicSymbols))

	printStringList("  Imported libraries", binary.ImportedLibraries)
	printImportedSymbols("  Imported symbols", binary.ImportedSymbols)
	printSections("  Sections", binary.Sections)
	printSegments("  Segments", binary.Segments)
	printSymbols("  Symbols", binary.Symbols)
	printSymbols("  Dynamic symbols", binary.DynamicSymbols)
}

func printStringList(title string, values []string) {
	if len(values) == 0 {
		return
	}

	fmt.Printf("%s:\n", title)
	for _, value := range values {
		fmt.Printf("    - %s\n", value)
	}
}

func printImportedSymbols(title string, symbols []ELFImportedSymbol) {
	if len(symbols) == 0 {
		return
	}

	fmt.Printf("%s:\n", title)
	for _, symbol := range symbols {
		fmt.Printf("    - %s", symbol.Name)
		if symbol.Version != "" {
			fmt.Printf(" version=%s", symbol.Version)
		}
		if symbol.Library != "" {
			fmt.Printf(" library=%s", symbol.Library)
		}
		fmt.Println()
	}
}

func printSections(title string, sections []ELFSection) {
	if len(sections) == 0 {
		return
	}

	fmt.Printf("%s:\n", title)
	for _, section := range sections {
		fmt.Printf("    - %s type=%s flags=%s addr=0x%x offset=%d size=%d link=%d info=%d align=%d entsize=%d\n",
			section.Name,
			section.Type,
			section.Flags,
			section.Address,
			section.Offset,
			section.Size,
			section.Link,
			section.Info,
			section.Alignment,
			section.EntrySize,
		)
	}
}

func printSegments(title string, segments []ELFSegment) {
	if len(segments) == 0 {
		return
	}

	fmt.Printf("%s:\n", title)
	for _, segment := range segments {
		fmt.Printf("    - type=%s flags=%s offset=%d vaddr=0x%x paddr=0x%x filesz=%d memsz=%d align=%d\n",
			segment.Type,
			segment.Flags,
			segment.Offset,
			segment.VirtualAddress,
			segment.PhysicalAddress,
			segment.FileSize,
			segment.MemorySize,
			segment.Alignment,
		)
	}
}

func printSymbols(title string, symbols []ELFSymbol) {
	if len(symbols) == 0 {
		return
	}

	fmt.Printf("%s:\n", title)
	for _, symbol := range symbols {
		fmt.Printf("    - %s section=%s value=0x%x size=%d info=%d other=%d",
			symbol.Name,
			symbol.Section,
			symbol.Value,
			symbol.Size,
			symbol.Info,
			symbol.Other,
		)
		if symbol.Version != "" {
			fmt.Printf(" version=%s", symbol.Version)
		}
		if symbol.Library != "" {
			fmt.Printf(" library=%s", symbol.Library)
		}
		fmt.Println()
	}
}

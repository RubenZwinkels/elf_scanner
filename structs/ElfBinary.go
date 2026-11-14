package structs

import "rzwinkels/elf_scanner/logger"

// ELFBinary houdt de verzamelde info bij van één ELF-bestand.
type ELFBinary struct {
	Path   string
	Name   string
	Size   int64
	SHA256 string

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
func (binary ELFBinary) Print(log *logger.Logger) {
	log.Print("===================================================================================")
	log.Printf("File: %s\n", binary.Name)
	log.Printf("  Path: %s\n", binary.Path)
	log.Printf("  Size: %d bytes\n", binary.Size)
	log.Printf("  SHA256: %s\n", binary.SHA256)
	log.Printf("  Mode: %s\n", binary.FileMode)
	log.Printf("  Modified: %s\n", binary.ModifiedAt)

	log.Println("  ELF header:")
	log.Printf("    Class: %s\n", binary.Class)
	log.Printf("    Endianness: %s\n", binary.Endianness)
	log.Printf("    Version: %s\n", binary.Version)
	log.Printf("    OS ABI: %s\n", binary.OSABI)
	log.Printf("    ABI version: %d\n", binary.ABIVersion)
	log.Printf("    Type: %s\n", binary.Type)
	log.Printf("    Architecture: %s\n", binary.Architecture)
	log.Printf("    Entry point: 0x%x\n", binary.EntryPoint)
	log.Printf("    Stripped: %t\n", binary.IsStripped)

	log.Println("  Counts:")
	log.Printf("    Sections: %d\n", binary.SectionCount)
	log.Printf("    Segments: %d\n", binary.SegmentCount)
	log.Printf("    Imported libraries: %d\n", len(binary.ImportedLibraries))
	log.Printf("    Imported symbols: %d\n", len(binary.ImportedSymbols))
	log.Printf("    Symbols: %d\n", len(binary.Symbols))
	log.Printf("    Dynamic symbols: %d\n", len(binary.DynamicSymbols))

	printStringList(log, "  Imported libraries", binary.ImportedLibraries)
	printImportedSymbols(log, "  Imported symbols", binary.ImportedSymbols)
	printSections(log, "  Sections", binary.Sections)
	printSegments(log, "  Segments", binary.Segments)
	printSymbols(log, "  Symbols", binary.Symbols)
	printSymbols(log, "  Dynamic symbols", binary.DynamicSymbols)
}

func printStringList(log *logger.Logger, title string, values []string) {
	if len(values) == 0 {
		return
	}

	log.Printf("%s:\n", title)
	for _, value := range values {
		log.Printf("    - %s\n", value)
	}
}

func printImportedSymbols(log *logger.Logger, title string, symbols []ELFImportedSymbol) {
	if len(symbols) == 0 {
		return
	}

	log.Printf("%s:\n", title)
	for _, symbol := range symbols {
		log.Printf("    - %s", symbol.Name)
		if symbol.Version != "" {
			log.Printf(" version=%s", symbol.Version)
		}
		if symbol.Library != "" {
			log.Printf(" library=%s", symbol.Library)
		}
		log.Println()
	}
}

func printSections(log *logger.Logger, title string, sections []ELFSection) {
	if len(sections) == 0 {
		return
	}

	log.Printf("%s:\n", title)
	for _, section := range sections {
		log.Printf("    - %s type=%s flags=%s addr=0x%x offset=%d size=%d link=%d info=%d align=%d entsize=%d\n",
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

func printSegments(log *logger.Logger, title string, segments []ELFSegment) {
	if len(segments) == 0 {
		return
	}

	log.Printf("%s:\n", title)
	for _, segment := range segments {
		log.Printf("    - type=%s flags=%s offset=%d vaddr=0x%x paddr=0x%x filesz=%d memsz=%d align=%d\n",
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

func printSymbols(log *logger.Logger, title string, symbols []ELFSymbol) {
	if len(symbols) == 0 {
		return
	}

	log.Printf("%s:\n", title)
	for _, symbol := range symbols {
		log.Printf("    - %s section=%s value=0x%x size=%d info=%d other=%d",
			symbol.Name,
			symbol.Section,
			symbol.Value,
			symbol.Size,
			symbol.Info,
			symbol.Other,
		)
		if symbol.Version != "" {
			log.Printf(" version=%s", symbol.Version)
		}
		if symbol.Library != "" {
			log.Printf(" library=%s", symbol.Library)
		}
		log.Println()
	}
}

package main

import (
	"debug/elf"
	"os"
	"path/filepath"
	"strconv"

	"rzwinkels/elf_scanner/structs"
)

// CollectELFBinaries leest een bestand of map en zet gevonden ELF files om naar ELFBinary structs.
func CollectELFBinaries(inputPath string) ([]structs.ELFBinary, error) {
	cleanPath, err := filepath.Abs(inputPath)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		binary, err := fileToELFBinary(cleanPath)
		if err != nil {
			return nil, err
		}

		return []structs.ELFBinary{binary}, nil
	}

	binaries := []structs.ELFBinary{}
	err = filepath.WalkDir(cleanPath, func(currentPath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return nil
		}

		binary, err := fileToELFBinary(currentPath)
		if err != nil {
			// Niet elk bestand in een map hoeft een ELF te zijn.
			return nil
		}

		binaries = append(binaries, binary)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return binaries, nil
}

func fileToELFBinary(path string) (structs.ELFBinary, error) {
	info, err := os.Stat(path)
	if err != nil {
		return structs.ELFBinary{}, err
	}

	elfFile, err := elf.Open(path)
	if err != nil {
		return structs.ELFBinary{}, err
	}
	defer elfFile.Close()

	symbols, symbolErr := elfFile.Symbols()
	dynamicSymbols, _ := elfFile.DynamicSymbols()
	importedSymbols, _ := elfFile.ImportedSymbols()
	importedLibraries, _ := elfFile.ImportedLibraries()

	binary := structs.ELFBinary{
		Path: path,
		Name: info.Name(),
		Size: info.Size(),

		FileMode:   info.Mode().String(),
		ModifiedAt: info.ModTime().Format("2006-01-02 15:04:05"),

		Class:        elfFile.Class.String(),
		Endianness:   elfFile.Data.String(),
		Version:      elfFile.Version.String(),
		OSABI:        elfFile.OSABI.String(),
		ABIVersion:   elfFile.ABIVersion,
		Type:         elfFile.Type.String(),
		Architecture: elfFile.Machine.String(),
		EntryPoint:   elfFile.Entry,

		SectionCount: len(elfFile.Sections),
		SegmentCount: len(elfFile.Progs),

		IsStripped: symbolErr != nil || len(symbols) == 0,

		ImportedLibraries: importedLibraries,
		ImportedSymbols:   mapImportedSymbols(importedSymbols),
		Symbols:           mapSymbols(symbols),
		DynamicSymbols:    mapSymbols(dynamicSymbols),

		Sections: mapSections(elfFile.Sections),
		Segments: mapSegments(elfFile.Progs),
	}

	return binary, nil
}

func mapSections(sections []*elf.Section) []structs.ELFSection {
	mappedSections := make([]structs.ELFSection, 0, len(sections))
	for _, section := range sections {
		mappedSections = append(mappedSections, structs.ELFSection{
			Name:      section.Name,
			Type:      section.Type.String(),
			Flags:     section.Flags.String(),
			Address:   section.Addr,
			Offset:    section.Offset,
			Size:      section.Size,
			Link:      section.Link,
			Info:      section.Info,
			Alignment: section.Addralign,
			EntrySize: section.Entsize,
		})
	}

	return mappedSections
}

func mapSegments(segments []*elf.Prog) []structs.ELFSegment {
	mappedSegments := make([]structs.ELFSegment, 0, len(segments))
	for _, segment := range segments {
		mappedSegments = append(mappedSegments, structs.ELFSegment{
			Type:            segment.Type.String(),
			Flags:           segment.Flags.String(),
			Offset:          segment.Off,
			VirtualAddress:  segment.Vaddr,
			PhysicalAddress: segment.Paddr,
			FileSize:        segment.Filesz,
			MemorySize:      segment.Memsz,
			Alignment:       segment.Align,
		})
	}

	return mappedSegments
}

func mapImportedSymbols(symbols []elf.ImportedSymbol) []structs.ELFImportedSymbol {
	mappedSymbols := make([]structs.ELFImportedSymbol, 0, len(symbols))
	for _, symbol := range symbols {
		mappedSymbols = append(mappedSymbols, structs.ELFImportedSymbol{
			Name:    symbol.Name,
			Version: symbol.Version,
			Library: symbol.Library,
		})
	}

	return mappedSymbols
}

func mapSymbols(symbols []elf.Symbol) []structs.ELFSymbol {
	mappedSymbols := make([]structs.ELFSymbol, 0, len(symbols))
	for _, symbol := range symbols {
		mappedSymbols = append(mappedSymbols, structs.ELFSymbol{
			Name:    symbol.Name,
			Info:    symbol.Info,
			Other:   symbol.Other,
			Section: strconv.Itoa(int(symbol.Section)),
			Value:   symbol.Value,
			Size:    symbol.Size,
			Version: symbol.Version,
			Library: symbol.Library,
		})
	}

	return mappedSymbols
}

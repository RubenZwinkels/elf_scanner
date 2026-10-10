package main

import (
	"os"
	"path/filepath"
	"rzwinkels/elf_scanner/structs"
)

// CollectELFBinaries leest een bestand of map en zet gevonden files om naar ELFBinary structs.
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
			return err
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

	return structs.ELFBinary{
		Path: path,
		Name: info.Name(),
		Size: info.Size(),
	}, nil
}

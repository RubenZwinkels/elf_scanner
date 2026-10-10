package structs

import "fmt"

// ELFBinary houdt de basisinformatie bij van één ELF-bestand.
// Later kunnen we hier ELF-header info, sections, hashes, entropy, etc. aan toevoegen.
type ELFBinary struct {
	Path string
	Name string
	Size int64
}

// Print toont één ELF-bestand op een leesbare manier.
func (binary ELFBinary) Print() {
	fmt.Printf("File: %s\n", binary.Name)
	fmt.Printf("  Path: %s\n", binary.Path)
	fmt.Printf("  Size: %d bytes\n", binary.Size)
}

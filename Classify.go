package main

import "rzwinkels/elf_scanner/structs"

// ClassifyELF is de facade voor alle heuristieken.
// Per heuristiek voegen we later echte score-logica toe.
func ClassifyELF(binary structs.ELFBinary) structs.ELFScore {
	score := structs.NewELFScore(binary)

	return score
}

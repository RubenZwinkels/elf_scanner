package heuristics

import (
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"rzwinkels/elf_scanner/structs"
)

type syscallRule struct {
	Name     string
	Category string
	Number   uint64 // Linux x86-64 syscallnummer; niet geldig op andere architecturen.
}

var objdumpInstruction = regexp.MustCompile(`^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*([a-zA-Z][a-zA-Z0-9.]*)\s*(.*)$`)

var syscallRules = []syscallRule{
	{"socket", "network", 41}, {"connect", "network", 42},
	{"sendto", "network", 44}, {"recvfrom", "network", 45},
	{"fork", "process", 57}, {"clone", "process", 56},
	{"execve", "process", 59}, {"execveat", "process", 322},
	{"openat", "filesystem", 257}, {"unlinkat", "filesystem", 263},
	{"chmod", "filesystem", 90},
	{"mmap", "memory", 9}, {"mprotect", "memory", 10},
}

// applySuspiciousSyscalls gebruikt objdump voor instructiegrenzen. Alleen een statisch
// zichtbare syscall met kort daarvoor een constante in eax/rax krijgt een naam.
// Imports van libc-wrappers zijn slechts kandidaten, geen bewezen syscall-uitvoering.
func applySuspiciousSyscalls(binary structs.ELFBinary, results *structs.ELFHeuristicResults) error {
	var result *structs.ELFHeuristicScore
	for i := range results.Heuristics {
		if results.Heuristics[i].ID == structs.HeuristicSuspiciousSyscalls {
			result = &results.Heuristics[i]
			break
		}
	}
	if result == nil {
		return nil
	}
	if binary.Architecture != "EM_X86_64" || binary.Class != "ELFCLASS64" {
		result.Evidence = []string{"Not evaluated: direct syscall decoding currently supports only Linux x86-64."}
		return nil
	}
	tool, err := exec.LookPath("objdump")
	if err != nil {
		result.Evidence = []string{"Not evaluated: objdump (binutils) is required for instruction-boundary disassembly."}
		return nil
	}
	output, err := exec.Command(tool, "-w", "-d", "-M", "intel", "--", binary.Path).CombinedOutput()
	if err != nil {
		result.Evidence = []string{fmt.Sprintf("Not evaluated: objdump failed: %v", err)}
		return nil
	}

	byNumber := make(map[uint64]syscallRule, len(syscallRules))
	byName := make(map[string]syscallRule, len(syscallRules))
	for _, rule := range syscallRules {
		byNumber[rule.Number] = rule
		byName[rule.Name] = rule
	}
	found := make(map[string][]string)
	wrappers := make(map[string][]string)
	var pending uint64
	var known bool
	var distance int
	var decoded int
	var unresolved int
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), ">:") {
			known = false // Geen registerwaarde over functiegrenzen heen meenemen.
		}
		match := objdumpInstruction.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		address := match[1]
		instruction := strings.ToLower(strings.TrimSpace(match[2] + " " + match[3]))
		if i := strings.Index(instruction, "#"); i >= 0 {
			instruction = strings.TrimSpace(instruction[:i])
		}
		decoded++
		if strings.HasPrefix(instruction, "call") {
			for name := range byName {
				if strings.Contains(instruction, "<"+name+"@plt>") {
					wrappers[name] = append(wrappers[name], "0x"+address)
				}
			}
		}
		if instruction == "syscall" {
			if known && distance <= 6 {
				if rule, ok := byNumber[pending]; ok {
					found[rule.Name] = append(found[rule.Name], "0x"+address)
				}
			} else {
				unresolved++
			}
			known = false
			continue
		}
		if strings.HasPrefix(instruction, "call") || strings.HasPrefix(instruction, "j") || strings.HasPrefix(instruction, "ret") {
			known = false
			continue
		}
		parts := strings.FieldsFunc(instruction, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		if len(parts) >= 3 && (parts[0] == "mov" || parts[0] == "movabs") && (parts[1] == "eax" || parts[1] == "rax") {
			pending, err = strconv.ParseUint(parts[2], 0, 64)
			known = err == nil
			distance = 0
			continue
		}
		if len(parts) >= 3 && parts[0] == "xor" && (parts[1] == "eax" || parts[1] == "rax") && parts[1] == parts[2] {
			pending, known, distance = 0, true, 0
			continue
		}
		if len(parts) >= 2 && (parts[1] == "eax" || parts[1] == "rax" || parts[1] == "ax" || parts[1] == "al" || parts[1] == "ah") {
			known = false // Een andere schrijfinstructie kan het syscallnummer wijzigen.
		}
		distance++
	}
	if decoded == 0 {
		result.Evidence = []string{"Not evaluated: objdump produced no disassembled instructions."}
		return nil
	}
	result.Evaluated = true
	result.Unit = "distinct statically identified calls"
	unique := make(map[string]bool)
	for name := range found {
		unique[name] = true
	}
	for name := range wrappers {
		unique[name] = true
	}
	result.Value = float64(len(unique))

	// Sorteer de uitvoer; map-iteratie in Go heeft geen vaste volgorde.
	names := make([]string, 0, len(found))
	for name := range found {
		names = append(names, name)
	}
	sort.Strings(names)
	categories := make(map[string]bool)
	for _, name := range names {
		rule := byName[name]
		categories[rule.Category] = true
		result.Evidence = append(result.Evidence, fmt.Sprintf("Direct syscall: %s (%s), call sites: %s", name, rule.Category, strings.Join(found[name], ", ")))
	}
	wrapperNames := make([]string, 0, len(wrappers))
	for name := range wrappers {
		wrapperNames = append(wrapperNames, name)
	}
	sort.Strings(wrapperNames)
	for _, name := range wrapperNames {
		rule := byName[name]
		categories[rule.Category] = true
		result.Evidence = append(result.Evidence, fmt.Sprintf("Library wrapper call: %s (%s), call sites: %s", name, rule.Category, strings.Join(wrappers[name], ", ")))
	}
	result.Triggered = categories["network"] && categories["process"]
	if result.Triggered {
		result.Evidence = append(result.Evidence, "Review: network and process calls both occur in this file; their relationship is not established.")
	}
	if unresolved > 0 {
		result.Evidence = append(result.Evidence, fmt.Sprintf("Unresolved syscall instructions: %d (number not safely determined)", unresolved))
	}
	for _, symbol := range binary.ImportedSymbols {
		name := strings.TrimPrefix(symbol.Name, "__libc_")
		if rule, ok := byName[name]; ok {
			result.Evidence = append(result.Evidence, fmt.Sprintf("Imported wrapper candidate: %s (%s); import alone does not prove a call", symbol.Name, rule.Category))
		}
	}
	if len(result.Evidence) == 0 {
		result.Evidence = []string{"No watched syscall number resolved; dynamic or indirect calls may be missed."}
	}
	return nil
}

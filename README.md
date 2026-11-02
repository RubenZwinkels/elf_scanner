# ELF scanner
Scans ands scores ELF's on a posibility of being malware.

# ELF heuristics

- [x] High section or segment entropy
- [x] Imported symbol count (measured; no threshold yet)
- [x] Section count (measured; no threshold yet)
- [x] Unusual section or segment size
- [ ] Suspicious section or segment permissions
- [x] Stripped symbols
- [ ] Missing or manipulated ELF header information
- [ ] Architecture-specific outliers
- [ ] Suspicious dynamic strings
- [ ] Suspicious statically identified syscalls

# Usage

Run with:

```bash
go run . -path ./path/to/file-or-directory
```

Example:

```bash
go run . -path ./samples
```

Output:

```text
Path received: ./samples
```

If `-path` is missing, the program exits with a usage message.

# Use of AI 
AI is used for:
- programming trivial logic, structure and calculations
- bug fixing
- refactoring

A human is used for:
- determining program architecture
- determining what heuristics to use and how
- determining the weights of heuristics
- evaluations

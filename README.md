# ELF scanner
Scans ands scores ELF's on a posibility of being malware.

# ELF heuristics

- [x] High section or segment entropy
- [x] Imported symbol count (measured; no threshold yet)
- [x] Section count (measured; no threshold yet)
- [x] Unusual section or segment size
- [x] Suspicious section or segment permissions
- [x] Stripped symbols
- [ ] Missing or manipulated ELF header information
- [ ] Architecture-specific outliers
- [ ] Suspicious dynamic strings
- [x] Suspicious statically identified syscalls

# Usage

Run with:

```bash
go run . -path ./path/to/file-or-directory
```

Example:

```bash
go run . -path ./samples
```

The minimum log level can be configured with `-log-level`:

```bash
go run . -path ./samples -log-level warning
```

Supported levels are `info`, `warning`, and `critical`. The default is `info`;
messages at the selected level and above are written to stderr.

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

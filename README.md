# ELF scanner
Scans ands scores ELF's on a posibility of being malware.
The score is based on this set of heuristics:
- nog niks

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


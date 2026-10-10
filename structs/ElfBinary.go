package structs

type ELFBinary struct {
    Path         string
    Name         string
    Size         int64
    SHA256       string
    Class        string
    Architecture string
    Endianness   string
    Type         string
    EntryPoint   uint64
    SectionCount int
    SegmentCount int
}

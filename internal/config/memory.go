package config

// Memory describes the ECU memory, backed by a firmware file. The input file
// is never modified: writes are applied in memory and persisted to OutputFile.
type Memory struct {
	File             string         `yaml:"file"`               // S-Record, Intel HEX or binary file; empty = blank memory
	Format           string         `yaml:"format"`             // srec | ihex | bin; empty = detect from extension/content
	BaseAddress      uint32         `yaml:"base_address"`       // load address of binary files
	OutputFile       string         `yaml:"output_file"`        // where writes are persisted; empty = memory only
	OutputFormat     string         `yaml:"output_format"`      // defaults to the input format (srec without input)
	ResumeFromOutput bool           `yaml:"resume_from_output"` // load OutputFile instead of File if it exists
	Fill             *uint8         `yaml:"fill"`               // value of bytes not present in the file; defaults to 0xFF
	Regions          []MemoryRegion `yaml:"regions"`            // empty = every segment of the file, readable and writable
}

// MemoryRegion is an addressable memory range with its own access rules.
type MemoryRegion struct {
	Name  string  `yaml:"name"`
	Start uint32  `yaml:"start"`
	Size  uint32  `yaml:"size"`
	Read  *Access `yaml:"read"`  // nil = readable in any session without security
	Write *Access `yaml:"write"` // nil = not writable
}

// ReadMemoryService configures ReadMemoryByAddress (0x23).
type ReadMemoryService struct {
	Service     `yaml:",inline"`
	MaxReadSize int `yaml:"max_read_size"` // 0 = unlimited
}

// resolvePaths makes relative file paths relative to dir.
func (m *Memory) resolvePaths(dir string) {
	resolve(dir, &m.File)
	resolve(dir, &m.OutputFile)
}

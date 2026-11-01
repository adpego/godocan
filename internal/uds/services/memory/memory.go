// Package memory implements the ECU memory, backed by a firmware file, and the
// services that access it by address: ReadMemoryByAddress (0x23) and
// WriteMemoryByAddress (0x3D).
package memory

import (
	"fmt"
	"os"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/memimage"
)

const defaultFill = 0xFF

// Region is an addressable memory range with its own access rules.
type Region struct {
	Name  string
	Start uint32
	Size  uint32
	Read  config.Access
	Write *config.Access // nil = not writable
}

func (r Region) contains(addr, size uint32) bool {
	return addr >= r.Start && uint64(addr)+uint64(size) <= uint64(r.Start)+uint64(r.Size)
}

// Memory is the ECU memory. The input file is never modified: writes are
// applied to the in-memory image and persisted to the output file on Flush.
// It must only be used with the ECU locked.
type Memory struct {
	image        *memimage.Image
	regions      []Region
	fill         byte
	outputFile   string
	outputFormat memimage.Format
	dirty        bool
}

// New loads the memory described by cfg. It returns (nil, nil) if cfg is nil.
func New(cfg *config.Memory) (*Memory, error) {
	if cfg == nil {
		return nil, nil
	}
	m := &Memory{image: &memimage.Image{}, fill: defaultFill, outputFile: cfg.OutputFile}
	if cfg.Fill != nil {
		m.fill = *cfg.Fill
	}

	format, err := memimage.ParseFormat(cfg.Format)
	if err != nil {
		return nil, err
	}
	outFormat, err := memimage.ParseFormat(cfg.OutputFormat)
	if err != nil {
		return nil, err
	}

	source := cfg.File
	if cfg.ResumeFromOutput && cfg.OutputFile != "" {
		if _, err := os.Stat(cfg.OutputFile); err == nil {
			source, format = cfg.OutputFile, outFormat
		}
	}
	if source != "" {
		img, detected, err := memimage.LoadFile(source, format, cfg.BaseAddress)
		if err != nil {
			return nil, err
		}
		m.image, format = img, detected
	}

	m.outputFormat = outFormat
	if m.outputFormat == "" {
		m.outputFormat = format
	}
	if m.outputFormat == "" && m.outputFile != "" {
		m.outputFormat = memimage.DetectFormat(m.outputFile, nil)
	}
	if m.outputFile != "" && m.outputFile == cfg.File {
		return nil, fmt.Errorf("output_file must differ from file: the input file is never modified")
	}

	if m.regions, err = buildRegions(cfg.Regions, m.image); err != nil {
		return nil, err
	}
	return m, nil
}

// buildRegions returns the configured regions or, if none, one readable and
// writable region per segment of the image.
func buildRegions(cfgs []config.MemoryRegion, img *memimage.Image) ([]Region, error) {
	if len(cfgs) == 0 {
		regions := make([]Region, 0, len(img.Segments))
		for i, s := range img.Segments {
			regions = append(regions, Region{
				Name:  fmt.Sprintf("segment%d", i),
				Start: s.Address,
				Size:  uint32(len(s.Data)),
				Write: &config.Access{},
			})
		}
		return regions, nil
	}

	regions := make([]Region, 0, len(cfgs))
	for _, c := range cfgs {
		if c.Size == 0 {
			return nil, fmt.Errorf("region %q: size must be positive", c.Name)
		}
		if uint64(c.Start)+uint64(c.Size) > 1<<32 {
			return nil, fmt.Errorf("region %q exceeds the 32-bit address space", c.Name)
		}
		r := Region{Name: c.Name, Start: c.Start, Size: c.Size, Write: c.Write}
		if c.Read != nil {
			r.Read = *c.Read
		}
		for _, o := range regions {
			if uint64(r.Start) < uint64(o.Start)+uint64(o.Size) && uint64(o.Start) < uint64(r.Start)+uint64(r.Size) {
				return nil, fmt.Errorf("region %q overlaps region %q", r.Name, o.Name)
			}
		}
		regions = append(regions, r)
	}
	return regions, nil
}

// Region returns the region that fully contains [addr, addr+size), if any.
func (m *Memory) Region(addr, size uint32) (Region, bool) {
	for _, r := range m.regions {
		if r.contains(addr, size) {
			return r, true
		}
	}
	return Region{}, false
}

// Read returns size bytes at addr; bytes missing from the file read as fill.
func (m *Memory) Read(addr, size uint32) []byte {
	return m.image.ReadFill(addr, int(size), m.fill)
}

// Write stores data at addr. Call Flush to persist it.
func (m *Memory) Write(addr uint32, data []byte) {
	m.image.Write(addr, data)
	m.dirty = true
}

// Flush persists pending writes to the output file, if one is configured.
func (m *Memory) Flush() error {
	if !m.dirty || m.outputFile == "" {
		return nil
	}
	if err := memimage.SaveFile(m.outputFile, m.image, m.outputFormat); err != nil {
		return err
	}
	m.dirty = false
	return nil
}

// Erase fills [addr, addr+size) with the fill value and persists it.
func (m *Memory) Erase(addr, size uint32) error {
	data := make([]byte, size)
	for i := range data {
		data[i] = m.fill
	}
	m.Write(addr, data)
	return m.Flush()
}

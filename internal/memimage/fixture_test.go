package memimage

import "testing"

// TestRepositoryFirmware checks that the sample firmware files are valid.
func TestRepositoryFirmware(t *testing.T) {
	for _, path := range []string{"../../firmware/engine_ecu.s19", "../../tests/e2e/firmware.s19"} {
		img, f, err := LoadFile(path, "", 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if f != FormatSREC || len(img.Segments) != 2 || img.Size() != 256+24 {
			t.Errorf("%s: format %s, %d segments, %d bytes", path, f, len(img.Segments), img.Size())
		}
	}
}

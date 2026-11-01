package config

// DTC is a diagnostic trouble code. The configured order is the chronological
// order used by the "first/most recent" ReadDTCInformation reports.
type DTC struct {
	Code                  uint32            `yaml:"code"` // 3-byte DTC number
	Name                  string            `yaml:"name"`
	Status                uint8             `yaml:"status"`                  // statusOfDTC bits (ISO 14229-1 D.2)
	FaultDetectionCounter int8              `yaml:"fault_detection_counter"` // -128..127
	Permanent             bool              `yaml:"permanent"`
	Severity              uint8             `yaml:"severity"`        // DTCSeverity: 0x20 maintenanceOnly, 0x40 checkAtNextHalt, 0x80 checkImmediately
	FunctionalUnit        uint8             `yaml:"functional_unit"` // DTCFunctionalUnit
	Snapshots             []DTCSnapshot     `yaml:"snapshots"`
	ExtendedData          []DTCExtendedData `yaml:"extended_data"`
}

// DTCSnapshot is a snapshot (freeze frame) record made of DIDs.
type DTCSnapshot struct {
	Record uint8      `yaml:"record"`
	DIDs   []DIDValue `yaml:"dids"`
}

// DTCExtendedData is an extended data record.
type DTCExtendedData struct {
	Record uint8 `yaml:"record"`
	Data   `yaml:",inline"`
}

// ReadDTCService configures ReadDTCInformation (0x19).
type ReadDTCService struct {
	Service                `yaml:",inline"`
	StatusAvailabilityMask *uint8        `yaml:"status_availability_mask"` // defaults to 0xFF
	DTCFormat              *uint8        `yaml:"dtc_format"`               // DTCFormatIdentifier; defaults to 0x01 (ISO 14229-1)
	ReportTypes            []SubFunction `yaml:"report_types"`             // empty = every implemented report type
}

// ClearDTCService configures ClearDiagnosticInformation (0x14).
type ClearDTCService struct {
	Service          `yaml:",inline"`
	StatusAfterClear *uint8     `yaml:"status_after_clear"` // defaults to 0x50 (testNotCompleted bits set)
	Groups           []DTCGroup `yaml:"groups"`             // besides 0xFFFFFF (all) and single DTCs
}

// DTCGroup is a named group of DTCs for ClearDiagnosticInformation.
type DTCGroup struct {
	ID    uint32   `yaml:"id"`
	Name  string   `yaml:"name"`
	Codes []uint32 `yaml:"codes"`
}

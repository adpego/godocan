package config

// Routine describes a routine identifier for RoutineControl (0x31). Each
// action (start, stop, results) is optional: a missing action answers NRC
// 0x12. Access applies to every action; Access.Sessions not matching answers
// NRC 0x31 as required for routines not supported in the active session.
type Routine struct {
	ID         uint16         `yaml:"id"`
	Name       string         `yaml:"name"`
	Access     Access         `yaml:"access"`
	DurationMs int            `yaml:"duration_ms"` // time the routine runs after start; 0 = until stopped (or instant without stop)
	Start      *RoutineAction `yaml:"start"`
	Stop       *RoutineAction `yaml:"stop"`
	Results    *RoutineAction `yaml:"results"`
}

// RoutineAction configures one RoutineControl sub-function of a routine.
type RoutineAction struct {
	Access          Access          `yaml:"access"`
	OptionLength    *int            `yaml:"option_length"`    // exact routineControlOptionRecord length; nil = any
	Response        Data            `yaml:"response"`         // routineStatusRecord returned on success
	RunningResponse *Data           `yaml:"running_response"` // results only: returned while the routine is running
	Cases           []RoutineCase   `yaml:"cases"`            // responses depending on the option record
	Effects         []RoutineEffect `yaml:"effects"`          // start only: side effects on the ECU
}

// RoutineCase overrides the response when the option record matches Request.
type RoutineCase struct {
	Request  Data  `yaml:"request"`
	Response Data  `yaml:"response"`
	NRC      uint8 `yaml:"nrc"` // if non-zero, answer with this NRC instead
}

// RoutineEffect is a side effect applied when a routine starts. Exactly one
// field must be set.
type RoutineEffect struct {
	EraseMemory *MemoryRange `yaml:"erase_memory"` // fill a memory range with the fill value
	SetDID      *DIDValue    `yaml:"set_did"`      // change the value of a DID
	SetDTC      *DTCStatus   `yaml:"set_dtc"`      // change a DTC status (ignored while DTC setting is off)
}

// DTCStatus is a status for a DTC.
type DTCStatus struct {
	Code   uint32 `yaml:"code"`
	Status uint8  `yaml:"status"`
}

// MemoryRange is an address range.
type MemoryRange struct {
	Start uint32 `yaml:"start"`
	Size  uint32 `yaml:"size"`
}

// DIDValue is a value for a data identifier.
type DIDValue struct {
	ID   uint16 `yaml:"id"`
	Data `yaml:",inline"`
}

package dtc

import (
	"maps"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
)

// ReadDTCInformation report types (ISO 14229-1).
const (
	ReportNumberOfDTCByStatusMask         uint8 = 0x01
	ReportDTCByStatusMask                 uint8 = 0x02
	ReportDTCSnapshotIdentification       uint8 = 0x03
	ReportDTCSnapshotRecordByDTCNumber    uint8 = 0x04
	ReportDTCExtDataRecordByDTCNumber     uint8 = 0x06
	ReportNumberOfDTCBySeverityMaskRecord uint8 = 0x07
	ReportDTCBySeverityMaskRecord         uint8 = 0x08
	ReportSeverityInformationOfDTC        uint8 = 0x09
	ReportSupportedDTC                    uint8 = 0x0A
	ReportFirstTestFailedDTC              uint8 = 0x0B
	ReportFirstConfirmedDTC               uint8 = 0x0C
	ReportMostRecentTestFailedDTC         uint8 = 0x0D
	ReportMostRecentConfirmedDTC          uint8 = 0x0E
	ReportDTCFaultDetectionCounter        uint8 = 0x14
	ReportDTCWithPermanentStatus          uint8 = 0x15
	ReportDTCExtDataRecordByRecordNumber  uint8 = 0x16
	ReportSupportedDTCExtDataRecord       uint8 = 0x1A
)

const (
	dtcFormatISO14229         uint8 = 0x01
	statusTestFailed          uint8 = 0x01
	statusConfirmedDTC        uint8 = 0x08
	allRecords                uint8 = 0xFF
	allOBDExtendedDataRecords uint8 = 0xFE
	firstOBDRecord            uint8 = 0x90
	lastOBDRecord             uint8 = 0xEF
)

type reader struct {
	store        *Store
	availability uint8
	format       uint8
	reports      uds.SubFunctions
}

// reportHandler builds the response data (after SID+0x40 and sub-function)
// or returns an NRC.
type reportHandler func(r *reader, req uds.Request) ([]byte, byte)

var reports = map[uint8]struct {
	length int // exact request length, SID included
	handle reportHandler
}{
	ReportNumberOfDTCByStatusMask:         {3, (*reader).numberByStatusMask},
	ReportDTCByStatusMask:                 {3, (*reader).byStatusMask},
	ReportDTCSnapshotIdentification:       {2, (*reader).snapshotIdentification},
	ReportDTCSnapshotRecordByDTCNumber:    {6, (*reader).snapshotRecord},
	ReportDTCExtDataRecordByDTCNumber:     {6, (*reader).extendedDataRecord},
	ReportSupportedDTC:                    {2, (*reader).supported},
	ReportFirstTestFailedDTC:              {2, chronological(statusTestFailed, false)},
	ReportFirstConfirmedDTC:               {2, chronological(statusConfirmedDTC, false)},
	ReportMostRecentTestFailedDTC:         {2, chronological(statusTestFailed, true)},
	ReportMostRecentConfirmedDTC:          {2, chronological(statusConfirmedDTC, true)},
	ReportDTCFaultDetectionCounter:        {2, (*reader).faultDetectionCounter},
	ReportDTCWithPermanentStatus:          {2, (*reader).permanent},
	ReportNumberOfDTCBySeverityMaskRecord: {4, (*reader).numberBySeverity},
	ReportDTCBySeverityMaskRecord:         {4, (*reader).bySeverity},
	ReportSeverityInformationOfDTC:        {5, (*reader).severityOfDTC},
	ReportDTCExtDataRecordByRecordNumber:  {3, (*reader).extDataByRecordNumber},
	ReportSupportedDTCExtDataRecord:       {3, (*reader).supportedExtDataRecord},
}

// RegisterRead adds ReadDTCInformation (0x19) to e. A nil cfg disables it.
func RegisterRead(e *uds.ECU, cfg *config.ReadDTCService, store *Store) error {
	if cfg == nil {
		return nil
	}
	r := &reader{store: store, availability: 0xFF, format: dtcFormatISO14229}
	if cfg.StatusAvailabilityMask != nil {
		r.availability = *cfg.StatusAvailabilityMask
	}
	if cfg.DTCFormat != nil {
		r.format = *cfg.DTCFormat
	}
	var err error
	r.reports, err = uds.NewSubFunctions(cfg.ReportTypes, slices.Collect(maps.Keys(reports)), func(id uint8) bool {
		_, ok := reports[id]
		return ok
	})
	if err != nil {
		return err
	}

	return e.Register(uds.Service{
		SID:            uds.SIDReadDTCInformation,
		Config:         cfg.Service,
		MinLength:      2,
		HasSubFunction: true,
		Handle:         r.handle,
	})
}

func (r *reader) handle(c *uds.Context, req uds.Request) []byte {
	if nrc := r.reports.Check(c, req.SubFunction); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	report := reports[req.SubFunction]
	if len(req.Data) != report.length {
		return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
	}
	data, nrc := report.handle(r, req)
	if nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	return uds.PositiveResponse(req.SID, append([]byte{req.SubFunction}, data...)...)
}

// status returns the status of d as reported (masked by availability).
func (r *reader) status(d *DTC) uint8 { return d.Status & r.availability }

func (r *reader) matching(mask uint8) []*DTC {
	var out []*DTC
	for _, d := range r.store.All() {
		if r.status(d)&mask != 0 {
			out = append(out, d)
		}
	}
	return out
}

func (r *reader) dtcAndStatus(dtcs []*DTC) []byte {
	out := []byte{r.availability}
	for _, d := range dtcs {
		out = append(out, d.codeBytes()...)
		out = append(out, r.status(d))
	}
	return out
}

func (r *reader) numberByStatusMask(req uds.Request) ([]byte, byte) {
	n := len(r.matching(req.Data[2]))
	return []byte{r.availability, r.format, byte(n >> 8), byte(n)}, 0
}

func (r *reader) byStatusMask(req uds.Request) ([]byte, byte) {
	return r.dtcAndStatus(r.matching(req.Data[2])), 0
}

func (r *reader) supported(uds.Request) ([]byte, byte) {
	return r.dtcAndStatus(r.store.All()), 0
}

func (r *reader) permanent(uds.Request) ([]byte, byte) {
	var dtcs []*DTC
	for _, d := range r.store.All() {
		if d.Permanent {
			dtcs = append(dtcs, d)
		}
	}
	return r.dtcAndStatus(dtcs), 0
}

// chronological reports the first or most recent DTC with a status bit set.
func chronological(bit uint8, mostRecent bool) reportHandler {
	return func(r *reader, _ uds.Request) ([]byte, byte) {
		dtcs := r.store.All()
		for i := range dtcs {
			d := dtcs[i]
			if mostRecent {
				d = dtcs[len(dtcs)-1-i]
			}
			if r.status(d)&bit != 0 {
				return r.dtcAndStatus([]*DTC{d}), 0
			}
		}
		return r.dtcAndStatus(nil), 0
	}
}

// faultDetectionCounter reports DTCs with a positive counter that have not
// matured yet (ISO 14229-1, 11.3.5.13).
func (r *reader) faultDetectionCounter(uds.Request) ([]byte, byte) {
	var out []byte
	for _, d := range r.store.All() {
		if d.FaultDetectionCounter > 0 && d.FaultDetectionCounter < 0x7F {
			out = append(out, d.codeBytes()...)
			out = append(out, byte(d.FaultDetectionCounter))
		}
	}
	return out, 0
}

func (r *reader) snapshotIdentification(uds.Request) ([]byte, byte) {
	var out []byte
	for _, d := range r.store.All() {
		for _, s := range d.snapshots {
			out = append(out, d.codeBytes()...)
			out = append(out, s.number)
		}
	}
	return out, 0
}

// lookup decodes DTCMaskRecord (3 bytes) and the record number.
func (r *reader) lookup(req uds.Request) (*DTC, uint8, byte) {
	code := uint32(req.Data[2])<<16 | uint32(req.Data[3])<<8 | uint32(req.Data[4])
	d := r.store.Get(code)
	if d == nil {
		return nil, 0, uds.NRCRequestOutOfRange
	}
	return d, req.Data[5], 0
}

func (r *reader) snapshotRecord(req uds.Request) ([]byte, byte) {
	d, number, nrc := r.lookup(req)
	if nrc != 0 {
		return nil, nrc
	}
	out := append(d.codeBytes(), r.status(d))
	found := false
	for _, s := range d.snapshots {
		if number == allRecords || number == s.number {
			out = append(out, s.number)
			out = append(out, s.data...)
			found = true
		}
	}
	if !found && number != allRecords {
		return nil, uds.NRCRequestOutOfRange
	}
	return out, 0
}

func (r *reader) extendedDataRecord(req uds.Request) ([]byte, byte) {
	d, number, nrc := r.lookup(req)
	if nrc != 0 {
		return nil, nrc
	}
	out := append(d.codeBytes(), r.status(d))
	found := false
	for _, x := range d.extendedData {
		obd := x.number >= firstOBDRecord && x.number <= lastOBDRecord
		if number == allRecords || number == x.number || (number == allOBDExtendedDataRecords && obd) {
			out = append(out, x.number)
			out = append(out, x.data...)
			found = true
		}
	}
	if !found && number != allRecords && number != allOBDExtendedDataRecords {
		return nil, uds.NRCRequestOutOfRange
	}
	return out, 0
}

// matchingSeverity returns the DTCs matching both masks (request bytes 2-3).
func (r *reader) matchingSeverity(req uds.Request) []*DTC {
	sevMask, statusMask := req.Data[2], req.Data[3]
	var out []*DTC
	for _, d := range r.store.All() {
		if d.Severity&sevMask != 0 && r.status(d)&statusMask != 0 {
			out = append(out, d)
		}
	}
	return out
}

// severityRecords encodes [severity functionalUnit DTC status]...
func (r *reader) severityRecords(dtcs []*DTC) []byte {
	out := []byte{r.availability}
	for _, d := range dtcs {
		out = append(out, d.Severity, d.FunctionalUnit)
		out = append(out, d.codeBytes()...)
		out = append(out, r.status(d))
	}
	return out
}

func (r *reader) numberBySeverity(req uds.Request) ([]byte, byte) {
	n := len(r.matchingSeverity(req))
	return []byte{r.availability, r.format, byte(n >> 8), byte(n)}, 0
}

func (r *reader) bySeverity(req uds.Request) ([]byte, byte) {
	return r.severityRecords(r.matchingSeverity(req)), 0
}

func (r *reader) severityOfDTC(req uds.Request) ([]byte, byte) {
	code := uint32(req.Data[2])<<16 | uint32(req.Data[3])<<8 | uint32(req.Data[4])
	d := r.store.Get(code)
	if d == nil {
		return nil, uds.NRCRequestOutOfRange
	}
	return r.severityRecords([]*DTC{d}), 0
}

// extDataByRecordNumber reports every DTC having extended data record N.
func (r *reader) extDataByRecordNumber(req uds.Request) ([]byte, byte) {
	number := req.Data[2]
	if number >= 0xF0 {
		return nil, uds.NRCRequestOutOfRange
	}
	out := []byte{number}
	for _, d := range r.store.All() {
		for _, x := range d.extendedData {
			if x.number == number {
				out = append(out, d.codeBytes()...)
				out = append(out, r.status(d))
				out = append(out, x.data...)
			}
		}
	}
	return out, 0
}

// supportedExtDataRecord lists the DTCs supporting extended data record N.
func (r *reader) supportedExtDataRecord(req uds.Request) ([]byte, byte) {
	number := req.Data[2]
	if number == 0x00 || number >= 0xFE {
		return nil, uds.NRCRequestOutOfRange
	}
	out := []byte{r.availability, number}
	for _, d := range r.store.All() {
		for _, x := range d.extendedData {
			if x.number == number {
				out = append(out, d.codeBytes()...)
				out = append(out, r.status(d))
			}
		}
	}
	return out, 0
}

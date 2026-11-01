// Package iocontrol implements InputOutputControlByIdentifier (0x2F) on top of
// the DID store: while the client controls a DID, its value (as read by 0x22)
// is the one imposed by the client.
package iocontrol

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/uds"
	"github.com/adpego/godocan/internal/uds/services/did"
)

// inputOutputControlParameter values (ISO 14229-1).
const (
	ReturnControlToECU  uint8 = 0x00
	ResetToDefault      uint8 = 0x01
	FreezeCurrentState  uint8 = 0x02
	ShortTermAdjustment uint8 = 0x03
)

type control struct {
	id         uint16
	access     config.Access
	parameters []uint8
	def        []byte
	enableMask bool

	controlled bool
	ecuValue   []byte // value to restore when control returns to the ECU
}

// Register adds InputOutputControlByIdentifier to e for the DIDs that have an
// io_control block. A nil cfg disables it. Every control returns to the ECU
// when the default session is entered (including resets and S3 timeouts).
func Register(e *uds.ECU, cfg *config.Service, dids []config.DID, store *did.Store) error {
	if cfg == nil {
		return nil
	}
	controls := make(map[uint16]*control)
	for _, d := range dids {
		if d.IOControl == nil {
			continue
		}
		c, err := newControl(d, store)
		if err != nil {
			return fmt.Errorf("DID 0x%04X: %w", d.ID, err)
		}
		controls[d.ID] = c
	}

	e.OnSessionChange(func(_, to uint8) {
		if to == uds.SessionDefault {
			for _, c := range controls {
				c.returnToECU(store)
			}
		}
	})

	return e.Register(uds.Service{
		SID:       uds.SIDInputOutputControlByIdentifier,
		Config:    *cfg,
		MinLength: 4,
		Handle: func(ctx *uds.Context, req uds.Request) []byte {
			return handle(ctx, req, controls, store)
		},
	})
}

func newControl(d config.DID, store *did.Store) (*control, error) {
	cur := store.Get(d.ID)
	if cur.VariableLength {
		return nil, fmt.Errorf("io_control requires a fixed-length DID")
	}
	c := &control{
		id:         d.ID,
		access:     d.IOControl.Access,
		parameters: d.IOControl.Parameters,
		def:        cur.Initial,
		enableMask: d.IOControl.EnableMask,
	}
	if len(c.parameters) == 0 {
		c.parameters = []uint8{ReturnControlToECU, ResetToDefault, FreezeCurrentState, ShortTermAdjustment}
	}
	for _, p := range c.parameters {
		if p > ShortTermAdjustment {
			return nil, fmt.Errorf("unsupported inputOutputControlParameter 0x%02X", p)
		}
	}
	if d.IOControl.Default != nil {
		v, err := d.IOControl.Default.Bytes()
		if err != nil {
			return nil, fmt.Errorf("default: %w", err)
		}
		if len(v) != len(cur.Initial) {
			return nil, fmt.Errorf("default has %d bytes, DID has %d", len(v), len(cur.Initial))
		}
		c.def = v
	}
	return c, nil
}

func (c *control) take(store *did.Store) {
	if !c.controlled {
		c.ecuValue = append([]byte(nil), store.Get(c.id).Value...)
		c.controlled = true
	}
}

func (c *control) returnToECU(store *did.Store) {
	if c.controlled {
		store.Set(c.id, c.ecuValue)
		c.controlled = false
	}
}

func handle(ctx *uds.Context, req uds.Request, controls map[uint16]*control, store *did.Store) []byte {
	id := binary.BigEndian.Uint16(req.Data[1:3])
	c, ok := controls[id]
	if !ok {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}
	if nrc := ctx.CheckAccess(c.access, uds.NRCRequestOutOfRange); nrc != 0 {
		return uds.NegativeResponse(req.SID, nrc)
	}
	param := req.Data[3]
	if !slices.Contains(c.parameters, param) {
		return uds.NegativeResponse(req.SID, uds.NRCRequestOutOfRange)
	}

	size := len(c.def)
	record := req.Data[4:]
	switch param {
	case ShortTermAdjustment:
		want := size
		if c.enableMask {
			want *= 2
		}
		if len(record) != want {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
	default:
		// Only a controlEnableMask may follow the other parameters.
		if len(record) != 0 && !(c.enableMask && len(record) == size) {
			return uds.NegativeResponse(req.SID, uds.NRCInvalidMessageLengthOrFormat)
		}
	}

	// The controlEnableMask (if any) is the last `size` bytes of the record:
	// only the bits it enables are affected.
	var mask []byte
	if c.enableMask && len(record) >= size {
		mask = record[len(record)-size:]
	}
	switch param {
	case ReturnControlToECU:
		if mask == nil || allOnes(mask) {
			c.returnToECU(store)
		} else if c.controlled {
			store.Set(c.id, merge(store.Get(c.id).Value, c.ecuValue, mask))
		}
	case ResetToDefault:
		c.take(store)
		store.Set(c.id, merge(store.Get(c.id).Value, c.def, mask))
	case FreezeCurrentState:
		c.take(store)
	case ShortTermAdjustment:
		c.take(store)
		store.Set(c.id, merge(store.Get(c.id).Value, record[:size], mask))
	}

	resp := uds.PositiveResponse(req.SID, req.Data[1], req.Data[2], param)
	return append(resp, store.Get(c.id).Value...)
}

// merge returns cur with the bits enabled by mask taken from value; a nil
// mask takes the whole value.
func merge(cur, value, mask []byte) []byte {
	if mask == nil {
		return append([]byte(nil), value...)
	}
	out := make([]byte, len(cur))
	for i := range out {
		out[i] = cur[i]&^mask[i] | value[i]&mask[i]
	}
	return out
}

func allOnes(b []byte) bool {
	for _, v := range b {
		if v != 0xFF {
			return false
		}
	}
	return true
}

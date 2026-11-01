package uds

import (
	"time"

	"github.com/adpego/godocan/internal/config"
)

// Request is a decoded UDS request handed to service handlers.
type Request struct {
	SID         byte
	SubFunction byte   // without the suppressPosRsp bit; only for services with sub-functions
	Data        []byte // whole request, SID included
}

// Handler processes a request that passed the generic checks. It runs with
// the ECU locked and may freely use the Context.
type Handler func(c *Context, req Request) []byte

// Service is a UDS service registered on an ECU. Before Handle is called the
// ECU checks, in ISO 14229-1 order: service supported, Config.Access (session
// -> 0x7F, security -> 0x33, forced NRC) and MinLength (0x13).
type Service struct {
	SID            byte
	Config         config.Service // access and response pending simulation
	MinLength      int            // minimum request length, SID included
	HasSubFunction bool           // enables suppressPosRspMsgIndicationBit handling
	Handle         Handler
}

// NegativeResponse builds a negative response (0x7F SID NRC).
func NegativeResponse(sid, nrc byte) []byte {
	return []byte{NegativeResponseSID, sid, nrc}
}

// PositiveResponse builds a positive response (SID+0x40 followed by data).
func PositiveResponse(sid byte, data ...byte) []byte {
	return append([]byte{sid + PositiveResponseBit}, data...)
}

func isNegative(resp []byte) bool {
	return len(resp) >= 3 && resp[0] == NegativeResponseSID
}

// suppressedOnFunctional lists the NRCs that must not be sent for functionally
// addressed requests (ISO 14229-1, 7.5).
func suppressedOnFunctional(nrc byte) bool {
	switch nrc {
	case NRCServiceNotSupported, NRCSubFunctionNotSupported, NRCRequestOutOfRange,
		NRCSubFunctionNotSupportedInActiveSession, NRCServiceNotSupportedInActiveSession:
		return true
	}
	return false
}

// Message is a UDS message sent by the ECU, after waiting Delay.
type Message struct {
	Data  []byte
	Delay time.Duration
}

// Client is the tester connection a request came from. Services use it to
// send unsolicited messages (periodic data, response on event) from any
// goroutine.
type Client interface {
	// Send delivers a UDS message to the client.
	Send(data []byte) error
	// Done is closed when the client disconnects.
	Done() <-chan struct{}
}

// PeriodicSender is implemented by clients with a dedicated channel for
// ReadDataByPeriodicIdentifier data, e.g. single unsegmented CAN frames
// (UUDT, ISO 15765-3). Other clients receive periodic data with Send.
type PeriodicSender interface {
	SendPeriodic(data []byte) error
}

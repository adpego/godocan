package uds

// Service identifiers (ISO 14229-1).
const (
	SIDDiagnosticSessionControl        byte = 0x10
	SIDECUReset                        byte = 0x11
	SIDClearDiagnosticInformation      byte = 0x14
	SIDReadDTCInformation              byte = 0x19
	SIDReadDataByIdentifier            byte = 0x22
	SIDReadScalingDataByIdentifier     byte = 0x24
	SIDReadDataByPeriodicIdentifier    byte = 0x2A
	SIDDynamicallyDefineDataIdentifier byte = 0x2C
	SIDReadMemoryByAddress             byte = 0x23
	SIDSecurityAccess                  byte = 0x27
	SIDAuthentication                  byte = 0x29
	SIDCommunicationControl            byte = 0x28
	SIDWriteDataByIdentifier           byte = 0x2E
	SIDInputOutputControlByIdentifier  byte = 0x2F
	SIDRoutineControl                  byte = 0x31
	SIDRequestDownload                 byte = 0x34
	SIDRequestUpload                   byte = 0x35
	SIDTransferData                    byte = 0x36
	SIDRequestTransferExit             byte = 0x37
	SIDRequestFileTransfer             byte = 0x38
	SIDWriteMemoryByAddress            byte = 0x3D
	SIDTesterPresent                   byte = 0x3E
	SIDSecuredDataTransmission         byte = 0x84
	SIDResponseOnEvent                 byte = 0x86
	SIDControlDTCSetting               byte = 0x85
	SIDLinkControl                     byte = 0x87

	NegativeResponseSID byte = 0x7F
	PositiveResponseBit byte = 0x40
	SuppressPosRspBit   byte = 0x80
)

// Diagnostic sessions (ISO 14229-1).
const (
	SessionDefault      uint8 = 0x01
	SessionProgramming  uint8 = 0x02
	SessionExtended     uint8 = 0x03
	SessionSafetySystem uint8 = 0x04
)

package uds

// Negative Response Codes (ISO 14229-1)
const (
	NRCGeneralReject                 byte = 0x10
	NRCServiceNotSupported           byte = 0x11
	NRCSubFunctionNotSupported       byte = 0x12
	NRCInvalidMessageLengthOrFormat  byte = 0x13
	NRCResponseTooLong               byte = 0x14
	NRCBusyRepeatRequest             byte = 0x21
	NRCConditionsNotCorrect          byte = 0x22
	NRCRequestSequenceError          byte = 0x24
	NRCNoResponseFromSubnetComponent byte = 0x25
	NRCFailurePreventsExecution      byte = 0x26
	NRCRequestOutOfRange             byte = 0x31
	NRCSecurityAccessDenied          byte = 0x33
	NRCInvalidKey                    byte = 0x35
	NRCExceededNumberOfAttempts      byte = 0x36
	NRCRequiredTimeDelayNotExpired   byte = 0x37

	// SecuredDataTransmission (ISO 15764)
	NRCGeneralSecurityViolation byte = 0x38
	NRCSecuredModeRequested     byte = 0x39
	NRCInsufficientProtection   byte = 0x3A

	// Authentication (ISO 14229-1:2020)
	NRCCertificateInvalidTimePeriod   byte = 0x50
	NRCCertificateInvalidSignature    byte = 0x51
	NRCCertificateInvalidChainOfTrust byte = 0x52
	NRCCertificateInvalidType         byte = 0x53
	NRCCertificateInvalidFormat       byte = 0x54
	NRCCertificateInvalidContent      byte = 0x55
	NRCCertificateInvalidScope        byte = 0x56
	NRCCertificateInvalidCertificate  byte = 0x57
	NRCOwnershipVerificationFailed    byte = 0x58
	NRCChallengeCalculationFailed     byte = 0x59
	NRCSettingAccessRightsFailed      byte = 0x5A
	NRCSessionKeyCreationFailed       byte = 0x5B
	NRCConfigurationDataUsageFailed   byte = 0x5C
	NRCDeAuthenticationFailed         byte = 0x5D

	NRCUploadDownloadNotAccepted              byte = 0x70
	NRCTransferDataSuspended                  byte = 0x71
	NRCProgrammingFailure                     byte = 0x72
	NRCWrongBlockSequenceCounter              byte = 0x73
	NRCRequestReceivedResponsePending         byte = 0x78
	NRCSubFunctionNotSupportedInActiveSession byte = 0x7E
	NRCServiceNotSupportedInActiveSession     byte = 0x7F

	// Vehicle manufacturer / conditions specific
	NRCRpmTooHigh                    byte = 0x81
	NRCRpmTooLow                     byte = 0x82
	NRCEngineRunning                 byte = 0x83
	NRCEngineNotRunning              byte = 0x84
	NRCEngineRunTimeTooLow           byte = 0x85
	NRCTemperatureTooHigh            byte = 0x86
	NRCTemperatureTooLow             byte = 0x87
	NRCSpeedTooHigh                  byte = 0x88
	NRCSpeedTooLow                   byte = 0x89
	NRCThrottleTooHigh               byte = 0x8A
	NRCThrottleTooLow                byte = 0x8B
	NRCTransmissionRangeNotInNeutral byte = 0x8C
	NRCTransmissionRangeNotInGear    byte = 0x8D
	NRCBrakeSwitchNotClosed          byte = 0x8F
	NRCShifterNotInPark              byte = 0x90
	NRCTorqueConverterClutchLocked   byte = 0x91
	NRCVoltageTooHigh                byte = 0x92
	NRCVoltageTooLow                 byte = 0x93

	// Manufacturer specific (0xF0–0xFE)
	NRCManufacturerSpecificF0 byte = 0xF0
	NRCManufacturerSpecificF1 byte = 0xF1
	NRCManufacturerSpecificF2 byte = 0xF2
	NRCManufacturerSpecificF3 byte = 0xF3
	NRCManufacturerSpecificF4 byte = 0xF4
	NRCManufacturerSpecificF5 byte = 0xF5
	NRCManufacturerSpecificF6 byte = 0xF6
	NRCManufacturerSpecificF7 byte = 0xF7
	NRCManufacturerSpecificF8 byte = 0xF8
	NRCManufacturerSpecificF9 byte = 0xF9
	NRCManufacturerSpecificFA byte = 0xFA
	NRCManufacturerSpecificFB byte = 0xFB
	NRCManufacturerSpecificFC byte = 0xFC
	NRCManufacturerSpecificFD byte = 0xFD
	NRCManufacturerSpecificFE byte = 0xFE
)

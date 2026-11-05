# godocan

A UDS (ISO 14229-1) ECU simulator in Go that talks over CAN: requests and
responses travel as ISO 15765-2 (ISO-TP) messages on a Linux SocketCAN
interface (real `can0` or virtual `vcan0`). It simulates a single, fully
configurable ECU for automotive diagnostics testing.

It is the CAN sibling of [godoip](../godoip) (same UDS core, services,
configuration and tests, DoIP replaced by CAN/ISO-TP).

Everything the ECU does is driven by [`config.yaml`](config.yaml): CAN
identifiers and ISO-TP parameters, which services exist, which sessions and
security levels they need, DIDs, DTCs, routines and a memory image loaded
from an S-Record / Intel HEX / binary file.

## Quick start

A virtual CAN interface is enough (CAN FD capable):

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

```sh
make run                          # go run ./cmd/server (uses ./config.yaml, vcan0)
go run ./cmd/server -config path/to/config.yaml
make test                         # Go unit tests (the SocketCAN test uses vcan0 if present)
make e2e                          # end-to-end tests with can-isotp + udsoncan on vcan0
make examples                     # call every service against a running server
candump vcan0                     # watch the frames (can-utils)
```

The e2e tests and examples use the Linux kernel ISO-TP stack (`can-isotp`
module, loaded automatically), an implementation independent from the
server's. The e2e tests refuse to start if an ECU already answers on
0x7E0 (e.g. `make run`), so they never test the wrong server.

## Python examples

[`examples/client.py`](examples/client.py) calls every UDS service against a
server started with the default `config.yaml`, printing each request
outcome. Services implemented by `udsoncan` use its client; 0x24, 0x2A,
0x84 and 0x86 are sent as raw bytes.

```sh
make run                                         # terminal 1
python examples/client.py                        # terminal 2: every section
python examples/client.py security memory        # only some sections
python examples/client.py --list                 # available sections
python examples/client.py --interface can0 --request 0x7E0 --response 0x7E8 --functional 0x7DF
```

## Implementation status

Legend: ✅ done · ⚠️ partial · ❌ not implemented

**Unit** = Go tests in the package. **E2E** = verified on a (virtual) CAN
bus with the kernel ISO-TP stack, [`can-isotp`](https://github.com/pylessard/python-can-isotp)
and [`udsoncan`](https://github.com/pylessard/python-udsoncan) (`tests/e2e`).

### UDS services (ISO 14229-1)

| SID  | Service                          | Implemented | Unit | E2E | Notes |
|------|----------------------------------|:-----------:|:----:|:---:|-------|
| 0x10 | DiagnosticSessionControl         | ✅ | ✅ | ✅ | Custom sessions, P2/P2* timings, allowed transitions, S3 timeout |
| 0x11 | ECUReset                         | ✅ | ✅ | ✅ | Configurable reset types, rapid power shutdown (0x04/0x05) |
| 0x14 | ClearDiagnosticInformation       | ✅ | ✅ | ✅ | All, single DTC, user-defined groups |
| 0x19 | ReadDTCInformation               | ⚠️ | ✅ | ✅ | 0x01–0x04, 0x06–0x0E, 0x14–0x16, 0x1A; user-defined memory and OBD reports missing, mirror memory not planned |
| 0x22 | ReadDataByIdentifier             | ✅ | ✅ | ✅ | Multiple DIDs per request, per-DID access |
| 0x23 | ReadMemoryByAddress              | ✅ | ✅ | ✅ | Backed by S-Record / Intel HEX / binary file, per-region access |
| 0x24 | ReadScalingDataByIdentifier      | ✅ | ✅ | ✅ | Per-DID scaling record, DID read access applies |
| 0x27 | SecurityAccess                   | ✅ | ✅ | ✅ | Fixed/random seeds, xor/add/not/fixed/seed algorithms, lockout |
| 0x28 | CommunicationControl             | ✅ | ✅ | ✅ | Control types 0x00–0x05, communication type filter, reset on default session |
| 0x29 | Authentication                   | ✅ | ✅ | ✅ | APCE (X.509, ECDSA/RSA/Ed25519, uni/bidirectional) and ACR (HMAC-SHA256) |
| 0x2A | ReadDataByPeriodicIdentifier     | ✅ | ✅ | ✅ | Slow/medium/fast rates, stop, message type 1/2, works with dynamic DIDs, optional UUDT frames |
| 0x2C | DynamicallyDefineDataIdentifier  | ✅ | ✅ | ✅ | By identifier, by memory address, clear; computed at read time |
| 0x2E | WriteDataByIdentifier            | ✅ | ✅ | ✅ | Writes are visible to later reads; fixed/variable length, volatile DIDs |
| 0x2F | InputOutputControlByIdentifier   | ✅ | ✅ | ✅ | Per-DID control, all 4 parameters, enable mask, auto return on default session |
| 0x31 | RoutineControl                   | ✅ | ✅ | ✅ | Start/stop/results, timed routines, option-based cases, effects |
| 0x34 | RequestDownload                  | ✅ | ✅ | ✅ | Buffered, applied and persisted on RequestTransferExit |
| 0x35 | RequestUpload                    | ✅ | ✅ | ✅ | Reads from the memory image |
| 0x36 | TransferData                     | ✅ | ✅ | ✅ | Block sequence counter (wraps), repeated blocks, max block length |
| 0x37 | RequestTransferExit              | ✅ | ✅ | ✅ | Rejects incomplete transfers |
| 0x38 | RequestFileTransfer              | ⚠️ | ✅ | ✅ | Add/delete/replace/read file, read dir in a sandboxed root; resumeFile not implemented |
| 0x3D | WriteMemoryByAddress             | ✅ | ✅ | ✅ | Persisted to a separate output file, the input file is never modified |
| 0x3E | TesterPresent                    | ✅ | ✅ | ✅ | |
| 0x83 | AccessTimingParameter            | ❌ |    |    | Withdrawn in ISO 14229-1:2020 |
| 0x84 | SecuredDataTransmission          | ⚠️ | ✅ | ✅ | ISO 14229-1:2020 layout, HMAC-SHA256 signatures and anti-replay; no encryption |
| 0x85 | ControlDTCSetting                | ✅ | ✅ | ✅ | Blocks DTC status updates, re-enabled in default session |
| 0x86 | ResponseOnEvent                  | ⚠️ | ✅ | ✅ | Events 0x00–0x06 (DTC status, timer, DID change); onComparisonOfValues not implemented |
| 0x87 | LinkControl                      | ✅ | ✅ | ✅ | Fixed/specific baudrate verification and transition |

### Generic UDS behaviour

| Feature                                                        | Implemented | Unit | E2E |
|----------------------------------------------------------------|:-----------:|:----:|:---:|
| ISO NRC order (0x11 → 0x7F → 0x33 → 0x13 → service checks)      | ✅ | ✅ | ✅ |
| Per-element access: sessions, security levels, forced NRC      | ✅ | ✅ | ✅ |
| suppressPosRspMsgIndicationBit                                 | ✅ | ✅ | ✅ |
| Functional addressing (NRC 0x11/0x12/0x31/0x7E/0x7F suppressed) | ✅ | ✅ | ✅ |
| S3 session timeout                                             | ✅ | ✅ | ✅ |
| Security relock on session change / reset                      | ✅ | ✅ | ✅ |
| Response pending (NRC 0x78) simulation, per service           | ✅ | ✅ | ✅ |

### CAN / ISO-TP (ISO 15765-2)

| Feature                                                          | Implemented | Unit | E2E | Notes |
|------------------------------------------------------------------|:-----------:|:----:|:---:|-------|
| SocketCAN raw socket, kernel filters on the request IDs          | ✅ | ✅ | ✅ | Classic and FD frames |
| 11-bit and 29-bit identifiers                                    | ✅ | ✅ | ✅ | Defaults 0x7E0/0x7E8/0x7DF, 29-bit functional 0x18DB33F1 |
| Single frames, first/consecutive frames, flow control            | ✅ | ✅ | ✅ | |
| Messages above 4095 bytes (escape first frame)                   | ✅ | ✅ | ✅ | Limited by `max_message_size` |
| Our flow control: block size, STmin                              | ✅ | ✅ | ✅ | |
| Tester flow control: BS, STmin (ms and 100-900 µs), WAIT, OVFLW  | ✅ | ✅ | ✅ | `wft_max` WAIT frames in a row |
| Timeouts N_Bs (flow control) and N_Cr (consecutive frame)        | ✅ | ✅ | ✅ | |
| Overflow flow control above `max_message_size`                   | ✅ | ✅ | ✅ | |
| Wrong sequence number / new message aborts a reception           | ✅ | ✅ | ✅ | |
| Padding (configurable byte) or minimal frames                    | ✅ | ✅ | ✅ | |
| CAN FD: escaped single frames, TX_DL 8–64, BRS                   | ✅ | ✅ | ✅ | |
| Functional addressing (single frames only)                       | ✅ | ✅ | ✅ | |
| Extended addressing (address byte)                               | ✅ | ✅ | ✅ | |
| Mixed addressing                                                 | ❌ |    |    | |
| Periodic data as UUDT single frames on its own ID (ISO 15765-3)  | ✅ | ✅ | ✅ | `periodic_response_id` |

## Configuration overview

See [`config.yaml`](config.yaml) for a complete, commented example.

- `can`: SocketCAN interface (default `can0`), `request_id` / `response_id`
  (default 0x7E0 / 0x7E8), `functional_id` (default 0x7DF, or 0x18DB33F1 with
  `extended_ids`), `addressing` (normal or extended with `rx_address`,
  `tx_address`, `functional_address`), CAN FD (`fd`, `bitrate_switch`,
  `tx_dl`), `padding`, our flow control (`block_size`, `st_min`),
  `max_message_size`, timeouts (`n_bs_ms`, `n_cr_ms`, `wft_max`) and
  `periodic_response_id` for UUDT periodic data.
- `ecu.services`: a service missing from this map is not supported (NRC 0x11);
  use `{}` to enable it with defaults. Every service accepts an `access` block
  and a `response_pending: {count, interval_ms}` block to simulate a slow ECU
  (NRC 0x78 before the final response).
- `access` (services, sessions, reset types, security levels, DIDs, memory
  regions, routines, DTC report types...):
  ```yaml
  access:
    sessions: [0x03]          # allowed active sessions (empty = any)
    security_levels: [0x01]   # one of these levels must be unlocked
    nrc: 0x22                 # always answer with this NRC
  ```
- `ecu.dids`: shared by 0x22 / 0x24 / 0x2C / 0x2E / 0x2F (and routine effects).
- `ecu.dtcs`: shared by 0x19 / 0x14 / 0x85 (and routine effects).
- `ecu.routines`: RoutineControl definitions.
- `ecu.memory`: firmware file used by 0x23 / 0x2C / 0x34–0x37 / 0x3D. Writes
  go to `output_file`, never to `file`.
- `request_file_transfer.root`: directory exposed by 0x38 (`firmware/files`
  in the example); paths can never escape it.

The `ecu` section is the same as godoip's: an ECU configuration can be moved
between both simulators by changing only `server` (DoIP) for `can`.

## Project layout

```
cmd/server/                 entry point (config loading, CAN defaults, wiring)
internal/config/            YAML configuration types
internal/can/               CAN frames, SocketCAN socket, in-memory bus for tests
internal/isotp/             ISO 15765-2 transport protocol
internal/server/            CAN server: ISO-TP links <-> UDS ECU
internal/memimage/          S-Record / Intel HEX / binary memory images
internal/uds/               UDS core: ECU, dispatcher, session/security state, access checks
internal/uds/udstest/       test helpers for services
internal/uds/services/      one package per service + services.New wiring them all
  session/ ecureset/ security/ testerpresent/ did/ dtc/ memory/ routine/
  iocontrol/ commcontrol/ linkcontrol/ transfer/ dddi/ periodic/ roe/ auth/ sdt/
tests/e2e/                  pytest suite using can-isotp + udsoncan (own config, firmware, test PKI)
examples/                   Python examples calling every service
firmware/                   sample firmware and file-transfer root for config.yaml
```

### Adding a service

1. Add its configuration type to `internal/config` and a field in `Services`.
2. Create `internal/uds/services/<name>/` with a `Register(e *uds.ECU, cfg ...)`
   function returning `nil` when `cfg` is nil, plus its tests.
3. Add one step to `internal/uds/services/services.go`.
4. Add an example to `config.yaml`, e2e tests and update the table above.

## Next steps

- ReadDTCInformation: user-defined memory (0x17–0x19), stored data by record
  number (0x05) and OBD reports (0x12, 0x13, 0x42, 0x55, 0x56). Mirror memory
  (0x0F–0x11) is not planned.
- ResponseOnEvent: onComparisonOfValues (0x07).
- RequestFileTransfer: resumeFile (0x06).
- SecuredDataTransmission: encryption.
- ISO-TP: mixed addressing; several ECUs (logical addresses) on one bus.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/adpego/godocan/internal/can"
	"github.com/adpego/godocan/internal/config"
	"github.com/adpego/godocan/internal/isotp"
	"github.com/adpego/godocan/internal/server"
	"github.com/adpego/godocan/internal/uds/services"
)

const (
	defaultInterface      = "can0"
	defaultRequestID      = 0x7E0
	defaultResponseID     = 0x7E8
	defaultFunctionalID   = 0x7DF      // OBD/UDS functional request, 11-bit
	defaultFunctionalID29 = 0x18DB33F1 // ISO 15765-4 functional request, 29-bit
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	applyCANDefaults(&cfg.CAN)

	ecu, err := services.New(cfg.ECU)
	if err != nil {
		log.Fatalf("invalid ECU config: %v", err)
	}
	srvCfg, err := buildServerConfig(cfg.CAN)
	if err != nil {
		log.Fatalf("invalid CAN config: %v", err)
	}

	c := cfg.CAN
	filters := []can.Filter{{ID: c.RequestID, Extended: c.ExtendedIDs}}
	if c.FunctionalID != nil {
		filters = append(filters, can.Filter{ID: *c.FunctionalID, Extended: c.ExtendedIDs})
	}
	// FD frames are always received; sending them needs fd: true.
	bus, err := can.Open(c.Interface, true, filters...)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.New(srvCfg, bus, ecu)
	if err != nil {
		log.Fatalf("invalid CAN config: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		bus.Close()
	}()

	log.Printf("ECU %q on %s: requests 0x%X, responses 0x%X, functional %s", cfg.ECU.Name, c.Interface,
		c.RequestID, c.ResponseID, functionalString(c))
	if err := srv.Serve(); err != nil {
		log.Fatal(err)
	}
}

func functionalString(c config.CANConfig) string {
	if c.FunctionalID == nil {
		return "disabled"
	}
	return fmt.Sprintf("0x%X", *c.FunctionalID)
}

// applyCANDefaults fills the settings left out of the configuration.
func applyCANDefaults(c *config.CANConfig) {
	if c.Interface == "" {
		c.Interface = defaultInterface
	}
	if c.RequestID == 0 && c.ResponseID == 0 {
		c.RequestID, c.ResponseID = defaultRequestID, defaultResponseID
	}
	if c.FunctionalID == nil {
		id := uint32(defaultFunctionalID)
		if c.ExtendedIDs {
			id = defaultFunctionalID29
		}
		c.FunctionalID = &id
	}
}

// buildServerConfig validates the CAN configuration and converts it.
func buildServerConfig(c config.CANConfig) (server.Config, error) {
	maxID := uint32(0x7FF)
	if c.ExtendedIDs {
		maxID = 0x1FFFFFFF
	}
	ids := map[string]uint32{"request_id": c.RequestID, "response_id": c.ResponseID}
	if c.FunctionalID != nil {
		ids["functional_id"] = *c.FunctionalID
	}
	if c.PeriodicID != nil {
		ids["periodic_response_id"] = *c.PeriodicID
	}
	for name, id := range ids {
		if id > maxID {
			return server.Config{}, fmt.Errorf("%s 0x%X does not fit in %d bits", name, id, map[bool]int{false: 11, true: 29}[c.ExtendedIDs])
		}
	}
	if c.RequestID == c.ResponseID {
		return server.Config{}, fmt.Errorf("request_id and response_id must differ")
	}
	if c.FunctionalID != nil && (*c.FunctionalID == c.ResponseID || (*c.FunctionalID == c.RequestID && c.Addressing != "extended")) {
		return server.Config{}, fmt.Errorf("functional_id must differ from request_id and response_id")
	}

	rx := isotp.Address{ID: c.RequestID, Extended: c.ExtendedIDs}
	tx := isotp.Address{ID: c.ResponseID, Extended: c.ExtendedIDs}
	var functional *isotp.Address
	if c.FunctionalID != nil {
		functional = &isotp.Address{ID: *c.FunctionalID, Extended: c.ExtendedIDs}
	}
	switch c.Addressing {
	case "", "normal":
	case "extended":
		rxAddr, txAddr := c.RxAddress, c.TxAddress
		rx.ExtAddr, tx.ExtAddr = &rxAddr, &txAddr
		if functional != nil {
			fa := rxAddr
			if c.FunctionalAddress != nil {
				fa = *c.FunctionalAddress
			}
			functional.ExtAddr = &fa
		}
	default:
		return server.Config{}, fmt.Errorf("addressing must be normal or extended, got %q", c.Addressing)
	}

	return server.Config{
		Physical: isotp.Config{
			Tx: tx, Rx: rx,
			FD: c.FD, BRS: c.BitrateSwitch, TxDL: c.TxDataLength, Padding: c.Padding,
			BlockSize: c.BlockSize, STmin: c.STmin, MaxRxSize: c.MaxMessageSize,
			NBs:    time.Duration(c.NBsMs) * time.Millisecond,
			NCr:    time.Duration(c.NCrMs) * time.Millisecond,
			WFTMax: c.WFTMax,
		},
		Functional: functional,
		PeriodicID: c.PeriodicID,
	}, nil
}

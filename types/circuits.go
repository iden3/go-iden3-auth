package types

import "github.com/iden3/go-circuits"

// CircuitData represents data that describes circuit
type CircuitData struct {
	ID          circuits.CircuitID
	Description string
	Metadata    string
}

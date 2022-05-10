package pubsignals

import (
	"github.com/iden3/go-circuits"
	"github.com/pkg/errors"
	"sync"
)

var signalsVerifierRegistry = map[circuits.CircuitID]Verifier{}
var circuitsLock = new(sync.RWMutex)

// RegisterVerifier is factory for pubsignals init.
// This is done during init() in the method's implementation
func RegisterVerifier(id circuits.CircuitID, v Verifier) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	signalsVerifierRegistry[id] = v
}

// nolint // register supported circuit
func init() {
	RegisterVerifier(circuits.AuthCircuitID, &Auth{})
	RegisterVerifier(circuits.AtomicQueryMTPCircuitID, &AtomicQueryMTP{})
}

// GetVerifier return specific public signals verifier
func GetVerifier(id circuits.CircuitID) (Verifier, error) {
	circuit, ok := signalsVerifierRegistry[id]
	if !ok {
		return nil, errors.New("public signals verifier for circuit %s id is not register")
	}
	return circuit, nil
}

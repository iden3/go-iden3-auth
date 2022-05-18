package pubsignals

import (
	"github.com/iden3/go-circuits"
	"github.com/pkg/errors"
	"sync"
)

var signalsVerifierRegistry = map[circuits.CircuitID]Verifier{}
var circuitsLock = new(sync.RWMutex)

// ErrUserStateIsNotValid declares that issuer state is invalid
var ErrUserStateIsNotValid = errors.New("user state is not valid")

// ErrIssuerClaimStateIsNotValid declares that issuer state is invalid
var ErrIssuerClaimStateIsNotValid = errors.New("issuer state is not valid")

// RegisterVerifier is factory for public signals init.
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

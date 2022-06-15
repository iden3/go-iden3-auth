package pubsignals

import (
	"github.com/iden3/go-circuits"
	"github.com/pkg/errors"
	"reflect"
	"sync"
)

var signalsVerifierRegistry = map[circuits.CircuitID]reflect.Type{}
var circuitsLock = new(sync.RWMutex)

// ErrUserStateIsNotValid declares that issuer state is invalid
var ErrUserStateIsNotValid = errors.New("user state is not valid")

// ErrIssuerClaimStateIsNotValid declares that issuer state is invalid
var ErrIssuerClaimStateIsNotValid = errors.New("issuer state is not valid")

// ErrIssuerNonRevocationClaimStateIsNotValid declares that issuer non-revocation state is invalid
var ErrIssuerNonRevocationClaimStateIsNotValid = errors.New("issuer state for non-revocation proofs is not valid")

// RegisterVerifier is factory for public signals init.
// This is done during init() in the method's implementation
func RegisterVerifier(id circuits.CircuitID, t reflect.Type) {
	circuitsLock.Lock()
	defer circuitsLock.Unlock()

	signalsVerifierRegistry[id] = t
}

// nolint // register supported circuit
func init() {
	RegisterVerifier(circuits.AuthCircuitID, reflect.TypeOf(Auth{}))
	RegisterVerifier(circuits.AtomicQuerySigCircuitID, reflect.TypeOf(AtomicQuerySig{}))
	RegisterVerifier(circuits.AtomicQueryMTPCircuitID, reflect.TypeOf(AtomicQueryMTP{}))

}

// GetVerifier return specific public signals verifier
func GetVerifier(id circuits.CircuitID) (Verifier, error) {
	verifierType, ok := signalsVerifierRegistry[id]
	if !ok {
		return nil, errors.New("public signals verifier for circuit is not registered")
	}

	return reflect.New(verifierType).Interface().(Verifier), nil
}

package loaders

import (
	"errors"
	"fmt"
	"os"

	"github.com/iden3/go-circuits/v2"
)

// VerificationKeyLoader load verification key bytes for specific circuit
type VerificationKeyLoader interface {
	Load(id circuits.CircuitID) ([]byte, error)
}

// FSKeyLoader read keys from filesystem
type FSKeyLoader struct {
	Dir string
}

// Load keys from embedded FS
func (m FSKeyLoader) Load(id circuits.CircuitID) ([]byte, error) {
	file, err := os.ReadFile(fmt.Sprintf("%s/%v.json", m.Dir, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrKeyNotFound
	}
	return file, err
}

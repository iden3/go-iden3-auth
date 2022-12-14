package loaders

import (
	"fmt"
	"os"

	"github.com/iden3/go-circuits"
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
	return os.ReadFile(fmt.Sprintf("%s/%v.json", m.Dir, id))
}

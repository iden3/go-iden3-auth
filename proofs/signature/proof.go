package signature

import (
	"errors"
	"github.com/iden3/go-auth/types"
)

// VerifyProof performs signature verification
func VerifyProof(m *types.SignatureProof) (err error) {
	return errors.New("method not implemented")
}

// ExtractMetadata extracts proof metadata
func ExtractMetadata(m *types.SignatureProof) (err error) {
	return errors.New("method not implemented")
}

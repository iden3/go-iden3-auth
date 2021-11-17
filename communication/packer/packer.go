package packer

import (
	"github.com/iden3/go-auth/types"
)

// Packer converts message to encrypted or encoded form
type Packer interface {
	// Pack a payload of type ContentType in an Iden3 compliant format using the sender identity
	Pack(contentType string, payload types.Message) ([]byte, error)
	// Unpack an envelope in Iden3 compliant format.
	Unpack(envelope []byte) (*types.Message, error)
}

package packer

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-auth/pkg/types"
)

// PlainMessagePacker is simple packer that doesn't use encryption / encoding
type PlainMessagePacker struct {
}

// Pack returns packed message to transport envelope
func (p *PlainMessagePacker) Pack(contentType string, payload types.Message) ([]byte, error) {

	var msgBytes []byte
	var err error
	switch contentType {
	case "application/json":
		msgBytes, err = json.Marshal(payload)
	default:
		return nil, fmt.Errorf("content type %s is not supported", contentType)
	}
	return msgBytes, err
}

// Unpack returns unpacked message from transport envelope
func (p *PlainMessagePacker) Unpack(envelope []byte) (types.Message, error) {

	var msg types.BasicMessage
	err := json.Unmarshal(envelope, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, err
}

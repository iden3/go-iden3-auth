package pubsignals

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

func verifyCredentialSubjectV3(
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader,
	metadata QueryMetadata,
) error {

	ctx := context.Background()

	// validate selectivity disclosure request
	if metadata.Operator == circuits.SD {
		return validateDisclosureV3(ctx, pubSig, metadata.FieldName,
			verifiablePresentation, schemaLoader)
	}

	// validate empty credential subject request
	if pubSig.Operator == circuits.NOOP && metadata.FieldName == "" {
		return verifyEmptyCredentialSubjectV3(pubSig)
	}

	if metadata.Operator != pubSig.Operator {
		return ErrRequestOperator
	}

	if len(metadata.Values) > len(pubSig.Value) {
		return ErrValuesSize
	}

	if pubSig.ValueArraySize != len(metadata.Values) {
		return errors.Errorf("values that used are not matching with expected in query. Size of value array size is different, expected %v, got %v ", len(metadata.Values), pubSig.ValueArraySize)
	}

	for i := 0; i < pubSig.ValueArraySize; i++ {
		if metadata.Values[i].Cmp(pubSig.Value[i]) != 0 {
			return ErrInvalidValues
		}
	}

	for i := pubSig.ValueArraySize; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(new(big.Int)) != 0 {
			return errors.New("signal values other then values queries must be set to zero")
		}
	}

	return nil
}

func validateDisclosureV3(ctx context.Context, pubSig *CircuitOutputs,
	key string, verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader) error {

	mvBig, err2 := fieldValueFromVerifiablePresentation(ctx, verifiablePresentation, schemaLoader, key)
	if err2 != nil {
		return err2
	}

	if pubSig.Operator != circuits.SD {
		return errors.New("invalid pub signal operator for selective disclosure")
	}

	if pubSig.OperatorOutput == nil || pubSig.OperatorOutput.Cmp(mvBig) != 0 {
		return errors.New("operator output should be equal to disclosed value")
	}
	for i := 0; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("public signal values must be zero")
		}
	}
	return nil
}

func verifyEmptyCredentialSubjectV3(
	pubSig *CircuitOutputs,
) error {
	if pubSig.Operator != circuits.NOOP {
		return errors.New("empty credentialSubject request available only for equal operation")
	}

	for i := 1; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("empty credentialSubject request not available for array of values")
		}
	}
	return nil
}

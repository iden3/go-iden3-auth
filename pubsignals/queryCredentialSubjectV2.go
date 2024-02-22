package pubsignals

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

func verifyCredentialSubjectV2(
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader,
	metadata QueryMetadata,
) error {

	ctx := context.Background()

	// validate selectivity disclosure request
	if metadata.Operator == circuits.SD {
		return validateDisclosureV2(ctx, pubSig, metadata.FieldName,
			verifiablePresentation, schemaLoader)
	}

	// validate empty credential subject request
	if metadata.Operator == circuits.NOOP && metadata.FieldName == "" && pubSig.Merklized == 1 {
		return verifyEmptyCredentialSubjectV2(pubSig, metadata.Path)
	}

	if metadata.Operator != pubSig.Operator {
		return ErrRequestOperator
	}

	if len(metadata.Values) > len(pubSig.Value) {
		return ErrValuesSize
	}

	if len(metadata.Values) < len(pubSig.Value) {
		diff := len(pubSig.Value) - len(metadata.Values)
		for diff > 0 {
			metadata.Values = append(metadata.Values, big.NewInt(0))
			diff--
		}
	}

	for i := 0; i < len(metadata.Values); i++ {
		if metadata.Values[i].Cmp(pubSig.Value[i]) != 0 {
			return ErrInvalidValues
		}
	}

	return nil
}

func validateDisclosureV2(ctx context.Context, pubSig *CircuitOutputs,
	key string, verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader) error {

	mvBig, err := fieldValueFromVerifiablePresentation(ctx, verifiablePresentation, schemaLoader, key)
	if err != nil {
		return err
	}

	if pubSig.Operator != circuits.EQ {
		return errors.New("selective disclosure available only for equal operation")
	}

	for i := 1; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("selective disclosure not available for array of values")
		}
	}

	if pubSig.Value[0].Cmp(mvBig) != 0 {
		return errors.New("different value between proof and disclosure value")
	}
	return nil
}

func verifyEmptyCredentialSubjectV2(
	pubSig *CircuitOutputs,
	credSubjectPath *merklize.Path,
) error {
	if pubSig.Operator != circuits.EQ {
		return errors.New("empty credentialSubject request available only for equal operation")
	}

	for i := 1; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("empty credentialSubject request not available for array of values")
		}
	}

	bi, err := credSubjectPath.MtEntry()
	if err != nil {
		return err
	}

	if pubSig.ClaimPathKey.Cmp(bi) != 0 {
		return errors.New("proof doesn't contain credentialSubject in claimPathKey")
	}

	return nil
}

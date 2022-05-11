package verification

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
)

//go:generate mockgen -destination=mock/blockchainCallerMock.go . BlockchainCaller

const (
	getStateContractMethod          = "getState"
	getTransitionInfoContractMethod = "getTransitionInfo"

	errCallArgumentEncodedErrorMessage = "wrong arguments were provided"
)

// BlockchainCaller is an interfact to call smart contract
type BlockchainCaller interface {
	// Call smart contract. For read operation.
	CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
}

// Unmarshaler converts contrcat data to provided interface
type Unmarshaler interface {
	Unmarshal([]interface{}) error
}

// StateVerificationResult can be the state verification result
type StateVerificationResult struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}

// VerifyState is used to verify identity state
// rpcURL - url to connect to the blockchain
// contractAddress is an address of state contract
// id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
// state is bigint string representation of identity state
func VerifyState(ctx context.Context, c BlockchainCaller, contractAddress string, id, state *big.Int) (StateVerificationResult, error) {
	stateContract := new(State)
	// get latest state for id from contract
	err := contractCall(ctx, c, contractAddress, getStateContractMethod, id, stateContract)
	if err != nil {
		return StateVerificationResult{}, err
	}
	if stateContract.Int64() == 0 {
		err = checkGenesisStateID(id, state)
		if err != nil {
			return StateVerificationResult{}, err
		}
		return StateVerificationResult{Latest: true, State: state.String()}, nil
	}
	if stateContract.String() != state.String() {

		// The non-empty state is returned, and it’s not equal to the state that the user has provided.
		// Get the time of the latest state and compare it to the transition time of state provided by the user.
		// The verification party can make a decision if it can accept this state based on that time frame

		transitionInfo := &TransitionInfo{}
		err := contractCall(ctx, c, contractAddress, getTransitionInfoContractMethod, state, transitionInfo)
		if err != nil {
			return StateVerificationResult{}, err
		}

		if transitionInfo.ID.Cmp(id) != 0 {
			return StateVerificationResult{}, errors.New("transition info contains invalid id")
		}

		if transitionInfo.ReplacedAtTimestamp.Int64() == 0 {
			return StateVerificationResult{}, errors.New("no information of transition for non-latest state")
		}
		return StateVerificationResult{
			Latest:              false,
			State:               state.String(),
			TransitionTimestamp: transitionInfo.ReplacedAtTimestamp.Int64(),
		}, nil
	}

	// The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
	return StateVerificationResult{Latest: true, State: state.String()}, nil
}

func contractCall(ctx context.Context, c BlockchainCaller, contractAddress, contractFunction string, param *big.Int, result Unmarshaler) error {

	data, err := StateABI.Pack(contractFunction, param)
	if data == nil {
		return errors.WithMessagef(err, "%s function: %s, param %v", errCallArgumentEncodedErrorMessage, contractFunction, param)
	}
	addr := common.HexToAddress(contractAddress)
	// 3. get state from contract
	res, err := c.CallContract(ctx, ethereum.CallMsg{
		To:   &addr,
		Data: data,
	}, nil)
	if err != nil {
		return err
	}

	outputs, err := StateABI.Unpack(contractFunction, res)
	if err != nil {
		return err
	}

	return result.Unmarshal(outputs)
}

func checkGenesisStateID(id, state *big.Int) error {

	IDFromState, err := core.IdGenesisFromIdenState(core.TypeDefault, state)
	if err != nil {
		return err
	}

	elemBytes := merkletree.NewElemBytesFromBigInt(id)
	IDFromParam, err := core.IDFromBytes(elemBytes[:31])
	if err != nil {
		return err
	}
	if IDFromState.String() != IDFromParam.String() {
		return errors.Errorf("ID from genesis state (%s) and provided (%s) don't match", IDFromState, IDFromParam.String())
	}
	return nil
}

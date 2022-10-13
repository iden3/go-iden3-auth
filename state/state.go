package state

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
)

// VerificationOptions is options for state verification
type VerificationOptions struct {
	Contract string
	RPCUrl   string
}

// ExtendedVerificationsOptions allows to set additional options
type ExtendedVerificationsOptions struct {
	VerificationOptions
	OnlyLatestStates             bool
	AcceptedStateTransitionDelay time.Duration
}

//go:generate mockgen -destination=mock/blockchainCallerMock.go . BlockchainCaller

const (
	getStateContractMethod          = "getState"
	getSmtRootTransitionsInfo       = "getSmtRootTransitionsInfo"
	getTransitionInfoContractMethod = "getTransitionInfo"

	errCallArgumentEncodedErrorMessage = "wrong arguments were provided"
)

// BlockchainCaller is an interface for smart contract call
type BlockchainCaller interface {
	// CallContract  cals smart contract. For read operation with single bigInt param
	CallContract(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error)
}

// Unmarshaler is used for contract call result parser
type Unmarshaler interface {
	Unmarshal([]interface{}) error
}

// ResolvedState can be the state verification result
type ResolvedState struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}

// Resolve is used to resolve identity state
// rpcURL - url to connect to the blockchain
// contractAddress is an address of state contract
// id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
// state is bigint string representation of identity state
func Resolve(ctx context.Context, c BlockchainCaller, contractAddress string, id, state *big.Int) (*ResolvedState, error) {
	stateContract := new(State)

	// сheck if id is genesis  - then we do need to resolve it.
	isGenesis, err := checkGenesisStateID(id, state)
	if err != nil {
		return nil, err
	}
	if isGenesis {
		// genesis state is latest
		return &ResolvedState{Latest: true, State: state.String()}, nil
	}
	// get latest state for id from contract
	err = contractCall(ctx, c, contractAddress, getStateContractMethod, id, stateContract)
	if err != nil {
		return nil, err
	}
	if stateContract.Int64() == 0 {
		return nil, errors.New("state is not genesis and not registered in the smart contract")
	}
	if stateContract.String() != state.String() {

		// The non-empty state is returned, and it’s not equal to the state that the user has provided.
		// Get the time of the latest state and compare it to the transition time of state provided by the user.
		// The verification party can make a decision if it can accept this state based on that time frame

		transitionInfo := &TransitionInfo{}
		err = contractCall(ctx, c, contractAddress, getTransitionInfoContractMethod, state, transitionInfo)
		if err != nil {
			return nil, err
		}

		if transitionInfo.ID.Cmp(id) != 0 {
			return nil, errors.New("transition info contains invalid id")
		}

		if transitionInfo.ReplacedAtTimestamp.Int64() == 0 {
			return nil, errors.New("no information of transition for non-latest state")
		}
		return &ResolvedState{
			Latest:              false,
			State:               state.String(),
			TransitionTimestamp: transitionInfo.ReplacedAtTimestamp.Int64(),
		}, nil
	}

	// The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
	return &ResolvedState{Latest: true, State: state.String()}, nil
}

// ResolveGlobalRoot is used to resolve global root
// rpcURL - url to connect to the blockchain
// contractAddress is an address of state contract
// state is bigint string representation of global root
func ResolveGlobalRoot(ctx context.Context, c BlockchainCaller, contractAddress string, state *big.Int) (*ResolvedState, error) {

	globalStateContract := new(State)

	// get the latest global state from contract
	err := contractCall(ctx, c, contractAddress, getSmtRootTransitionsInfo, state, globalStateContract)
	if err != nil {
		return nil, err
	}
	if globalStateContract.Int64() == 0 {
		return nil, errors.New("state not registered in the smart contract")
	}
	if globalStateContract.String() != state.String() {
		return nil, errors.New("not the latest global root")
	}

	// The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
	return &ResolvedState{Latest: true, State: state.String()}, nil
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

func checkGenesisStateID(id, state *big.Int) (bool, error) {

	stateHash, err := merkletree.NewHashFromBigInt(state)
	if err != nil {
		return false, err
	}

	IDFromState, err := core.IdGenesisFromIdenState(core.TypeDefault, stateHash.BigInt())
	if err != nil {
		return false, err
	}

	idBytes := merkletree.NewElemBytesFromBigInt(id)
	IDFromParam, err := core.IDFromBytes(idBytes[:31])
	if err != nil {
		return false, err
	}
	if IDFromState.String() != IDFromParam.String() {
		return false, nil
	}
	return true, nil
}

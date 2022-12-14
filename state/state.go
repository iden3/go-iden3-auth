package state

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
)

var zero = big.NewInt(0)

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

// StateGetter return user's state info by user's ID
//
//go:generate mockgen -destination=mock/StateGetterMock.go . StateGetter
//nolint:revive // we have two different getters for the state in one pkg
type StateGetter interface {
	GetStateInfoById(opts *bind.CallOpts, id *big.Int) (StateInfo, error)
}

// GISTGetter return global state info by state
//
//go:generate mockgen -destination=mock/GISTGetterMock.go . GISTGetter
type GISTGetter interface {
	GetGISTRootInfo(opts *bind.CallOpts, state *big.Int) (RootInfo, error)
}

// ResolvedState can be the state verification result
type ResolvedState struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	Genesis             bool   `json:"genesis"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}

// Resolve is used to resolve identity state
// rpcURL - url to connect to the blockchain
// contractAddress is an address of state contract
// id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
// state is bigint string representation of identity state
func Resolve(ctx context.Context, getter StateGetter, id, state *big.Int) (*ResolvedState, error) {
	// сheck if id is genesis  - then we do need to resolve it.
	isGenesis, err := checkGenesisStateID(id, state)
	if err != nil {
		return nil, err
	}

	stateInfo, err := getter.GetStateInfoById(&bind.CallOpts{Context: ctx}, id)
	if err != nil {
		return nil, err
	}

	if stateInfo.State.Cmp(zero) == 0 {
		if !isGenesis {
			return nil, errors.New("state is not genesis and not registered in the smart contract")
		}
		return &ResolvedState{Latest: true, Genesis: isGenesis, State: state.String()}, nil
	}
	if stateInfo.Id.Cmp(id) != 0 {
		return nil, errors.New("transition info contains invalid id")
	}

	if stateInfo.State.Cmp(state) != 0 {
		if stateInfo.ReplacedAtTimestamp.Cmp(zero) == 0 {
			return nil, errors.New("no information of transition for non-latest state")
		}
		return &ResolvedState{
			Latest:              false,
			Genesis:             isGenesis,
			State:               state.String(),
			TransitionTimestamp: stateInfo.ReplacedAtTimestamp.Int64(),
		}, nil
	}

	// The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
	return &ResolvedState{Latest: true, Genesis: isGenesis, State: state.String()}, nil
}

// ResolveGlobalRoot is used to resolve global root
// rpcURL - url to connect to the blockchain
// contractAddress is an address of state contract
// state is bigint string representation of global root
func ResolveGlobalRoot(ctx context.Context, getter GISTGetter, state *big.Int) (*ResolvedState, error) {
	globalStateInfo, err := getter.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, state)
	if err != nil {
		return nil, err
	}

	if globalStateInfo.CreatedAtTimestamp.Cmp(zero) == 0 {
		return nil, errors.New("gist state not registered in the smart contract")
	}
	if globalStateInfo.Root.Cmp(state) != 0 {
		return nil, errors.New("gist info contains invalid state")
	}
	if globalStateInfo.ReplacedByRoot.Cmp(zero) != 0 {
		return &ResolvedState{
			State:               state.String(),
			Latest:              false,
			TransitionTimestamp: globalStateInfo.ReplacedAtTimestamp.Int64(),
		}, nil
	}
	return &ResolvedState{
		State:               state.String(),
		Latest:              true,
		TransitionTimestamp: 0,
	}, nil
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

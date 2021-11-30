package verification

import (
	"context"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
	"math/big"
)

const (
	getStateContractMethod               = "getState"
	getTransitionTimestampContractMethod = "getTransitionTimestamp"

	errRPCClientCreationMessage        = "couldn't create rpc client"
	errCallArgumentEncodedErrorMessage = "wrong arguments were provided"
)

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
func VerifyState(ctx context.Context, rpcURL, contractAddress string, id, state *big.Int) (StateVerificationResult, error) {

	c, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return StateVerificationResult{}, errors.WithMessage(err, errRPCClientCreationMessage)
	}

	defer c.Close()

	// get latest state for id from contract
	stateContract, err := contractCall(ctx, c, contractAddress, getStateContractMethod, id)
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

		timestamp, err := contractCall(ctx, c, contractAddress, getTransitionTimestampContractMethod, state)
		if err != nil {
			return StateVerificationResult{}, err
		}
		if timestamp.Int64() == 0 {
			return StateVerificationResult{}, errors.New("no information of transition for non-latest state")
		}
		return StateVerificationResult{Latest: false, State: state.String(), TransitionTimestamp: timestamp.Int64()}, nil
	}

	// The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
	return StateVerificationResult{Latest: true, State: state.String()}, nil
}

func contractCall(ctx context.Context, c *ethclient.Client, contractAddress, contractFunction string, param *big.Int) (*big.Int, error) {

	data, err := StateABI.Pack(contractFunction, param)
	if data == nil {
		return nil, errors.WithMessagef(err, "%s function: %s, param %v", errCallArgumentEncodedErrorMessage, contractFunction, param)
	}
	addr := common.HexToAddress(contractAddress)
	// 3. get state from contract
	res, err := c.CallContract(ctx, ethereum.CallMsg{
		To:   &addr,
		Data: data,
	}, nil)
	if err != nil {
		return nil, err
	}
	outputs, err := StateABI.Unpack(getStateContractMethod, res)
	if err != nil {
		return nil, err
	}
	if outputs[0] == nil {
		return nil, errors.New("no state output")
	}
	outputBigInt, ok := outputs[0].(*big.Int)
	if !ok {
		return nil, errors.New("expected result is not big integer")
	}
	return outputBigInt, nil
}

func checkGenesisStateID(id, state *big.Int) error {

	stateHash := merkletree.NewHashFromBigInt(state)
	IDFromState := core.IdGenesisFromIdenState(stateHash).String()

	elemBytes := merkletree.NewElemBytesFromBigInt(id)
	IDFromParam, err := core.IDFromBytes(elemBytes[:31])
	if err != nil {
		return err
	}
	if IDFromState != IDFromParam.String() {
		return errors.Errorf("ID from genesis state (%s) and provided (%s) don't match", IDFromState, IDFromParam.String())
	}
	return nil
}

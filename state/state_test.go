package state

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/iden3/go-iden3-auth/state/mock"
)

var mockContractAddress = "0xE4F771f86B34BF7B323d9130c385117Ec39377c3" // before transition
var userID, _ = new(big.Int).SetString("346391769520471636532535596518006847163363135146657332490940275587923509248", 10)
var userGenesisState, _ = new(big.Int).SetString("371135506535866236563870411357090963344408827476607986362864968105378316288", 10)
var userState, _ = new(big.Int).SetString("16751774198505232045539489584666775489135471631443877047826295522719290880931", 10)

// abi types.
var (
	uint256Ty, _ = abi.NewType("uint256", "", []abi.ArgumentMarshaling{
		{Name: "", Type: "uint256"},
	})
	uint64Ty, _ = abi.NewType("uint64", "", []abi.ArgumentMarshaling{
		{Name: "", Type: "uint64"},
	})
)

func TestVerifyState_CheckToGenesisState(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return empty state from blockchain
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	b, err := args.Pack(new(big.Int))
	require.NoError(t, err)

	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	latestState, err := Resolve(context.Background(), m, mockContractAddress, userID, userGenesisState)

	require.NoError(t, err)
	require.True(t, latestState.Latest)
	require.True(t, latestState.Genesis)
	require.Equal(t, userGenesisState.String(), latestState.State)

	ctrl.Finish()
}

func TestVerifyState_LocalStateIsLatestState(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return User state from blockchain.
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	b, err := args.Pack(userState)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	latestState, err := Resolve(context.Background(), m, mockContractAddress, userID, userState)
	require.NoError(t, err)
	require.True(t, latestState.Latest)
	require.False(t, latestState.Genesis)

	require.Equal(t, userState.String(), latestState.State)

	ctrl.Finish()
}

func TestVerifyState_LatestStateExistOnBlockchain(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return User state from blockchain.
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	b, err := args.Pack(userGenesisState)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	// return information about transition state from blockchain.
	// put information about state transition.
	args = abi.Arguments{
		{Type: uint256Ty, Name: ""}, // ReplacedAtTimestamp
		{Type: uint256Ty, Name: ""}, // CreatedAtTimestamp
		{Type: uint64Ty, Name: ""},  // ReplacedAtBlock
		{Type: uint64Ty, Name: ""},  // CreatedAtBlock
		{Type: uint256Ty, Name: ""}, // ID
		{Type: uint256Ty, Name: ""}, // ReplacedBy
	}
	replacedTime := big.NewInt(100)
	b, err = args.Pack(
		replacedTime,  // ReplacedAtTimestamp
		big.NewInt(0), // CreatedAtTimestamp
		uint64(0),     // ReplacedAtBlock
		uint64(0),     // CreatedAtBlock
		userID,        // ID
		big.NewInt(0), // ReplacedBy
	)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

	resolvedState, err := Resolve(context.Background(), m, mockContractAddress, userID, userState)
	require.NoError(t, err)
	require.False(t, resolvedState.Latest)
	require.False(t, resolvedState.Genesis)
	require.Equal(t, userState.String(), resolvedState.State)
	require.Equal(t, replacedTime.Int64(), resolvedState.TransitionTimestamp)

	ctrl.Finish()
}

func TestVerifyState_ErrorCase_StateNotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return User state from blockchain.
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	// zero mean that state in smart contract not found.
	b, err := args.Pack(big.NewInt(0))
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	_, err = Resolve(context.Background(), m, mockContractAddress, userID, userState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "state is not genesis and not registered in the smart contract")

	ctrl.Finish()
}

func TestVerifyState_ErrorCase_TransactionInfoContainsIncorrectID(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return User state from blockchain.
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	b, err := args.Pack(userGenesisState)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	// return information about transition state from blockchain.
	// put information about state transition.
	args = abi.Arguments{
		{Type: uint256Ty, Name: ""}, // ReplacedAtTimestamp
		{Type: uint256Ty, Name: ""}, // CreatedAtTimestamp
		{Type: uint64Ty, Name: ""},  // ReplacedAtBlock
		{Type: uint64Ty, Name: ""},  // CreatedAtBlock
		{Type: uint256Ty, Name: ""}, // ID
		{Type: uint256Ty, Name: ""}, // ReplacedBy
	}
	replacedTime := big.NewInt(100)
	b, err = args.Pack(
		replacedTime,  // ReplacedAtTimestamp
		big.NewInt(0), // CreatedAtTimestamp
		uint64(0),     // ReplacedAtBlock
		uint64(0),     // CreatedAtBlock
		big.NewInt(0), // ID // PUT INCORRECT ID.
		big.NewInt(0), // ReplacedBy
	)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

	_, err = Resolve(context.Background(), m, mockContractAddress, userID, userState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "transition info contains invalid id")

	ctrl.Finish()
}

func TestVerifyState_ErrorCase_TransactionInfoUnknownTransitionTime(t *testing.T) {
	ctrl := gomock.NewController(t)
	m := mock_verification.NewMockBlockchainCaller(ctrl)

	// return User state from blockchain.
	args := abi.Arguments{
		{Type: uint256Ty, Name: ""},
	}
	b, err := args.Pack(userGenesisState)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), nil).Return(b, nil)

	// return information about transition state from blockchain.
	// put information about state transition.
	args = abi.Arguments{
		{Type: uint256Ty, Name: ""}, // ReplacedAtTimestamp
		{Type: uint256Ty, Name: ""}, // CreatedAtTimestamp
		{Type: uint64Ty, Name: ""},  // ReplacedAtBlock
		{Type: uint64Ty, Name: ""},  // CreatedAtBlock
		{Type: uint256Ty, Name: ""}, // ID
		{Type: uint256Ty, Name: ""}, // ReplacedBy
	}

	b, err = args.Pack(
		big.NewInt(0), // ReplacedAtTimestamp // STATE IN BLOCKCHAIN was not replace.
		big.NewInt(0), // CreatedAtTimestamp
		uint64(0),     // ReplacedAtBlock
		uint64(0),     // CreatedAtBlock
		userID,        // ID
		big.NewInt(0), // ReplacedBy
	)
	require.NoError(t, err)
	m.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

	_, err = Resolve(context.Background(), m, mockContractAddress, userID, userState)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no information of transition for non-latest state")

	ctrl.Finish()
}

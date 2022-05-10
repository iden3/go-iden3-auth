package state

import (
	"context"
	"errors"
	"github.com/iden3/go-iden3-auth/state/mock"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

var mockContractAddress = "0xE4F771f86B34BF7B323d9130c385117Ec39377c3" // before transition
var mockGenesisID, _ = new(big.Int).SetString("371135506535866236563870411357090963344408827476607986362864968105378316288", 10)
var mockGenesisState, _ = new(big.Int).SetString("16751774198505232045539489584666775489135471631443877047826295522719290880931", 10)

// abi types.
var (
	uint256Ty, _ = abi.NewType("uint256", "", []abi.ArgumentMarshaling{
		{Name: "", Type: "uint256"},
	})
	uint64Ty, _ = abi.NewType("uint64", "", []abi.ArgumentMarshaling{
		{Name: "", Type: "uint64"},
	})
)

func TestVerifyState(t *testing.T) {
	tests := []struct {
		name        string
		prepareMock func(mbc *mock_verification.MockBlockchainCaller, t *testing.T)
		expected    VerificationResult
	}{
		{
			name: "verify state without record in block-chain",
			prepareMock: func(mbc *mock_verification.MockBlockchainCaller, t *testing.T) {
				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(make([]byte, 32), nil)
			},
			expected: VerificationResult{
				State:               mockGenesisState.String(),
				Latest:              true,
				TransitionTimestamp: 0,
			},
		},
		{
			name: "genesis state exists in block-chain",
			prepareMock: func(mbc *mock_verification.MockBlockchainCaller, t *testing.T) {
				// put genesis state in block-chain.
				args := abi.Arguments{
					{Type: uint256Ty, Name: ""},
				}
				b, err := args.Pack(mockGenesisState)
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)
			},
			expected: VerificationResult{Latest: true, State: mockGenesisState.String()},
		},
		{
			name: "the blockchain contains a newer state record",
			prepareMock: func(mbc *mock_verification.MockBlockchainCaller, t *testing.T) {
				// put old state in block-chain.
				args := abi.Arguments{
					{Type: uint256Ty, Name: ""},
				}
				b, err := args.Pack(big.NewInt(100))
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

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
					big.NewInt(100), // ReplacedAtTimestamp
					big.NewInt(0),   // CreatedAtTimestamp
					uint64(0),       // ReplacedAtBlock
					uint64(0),       // CreatedAtBlock
					mockGenesisID,   // ID
					big.NewInt(0),   // ReplacedBy
				)
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)
			},
			expected: VerificationResult{
				State:               mockGenesisState.String(),
				Latest:              false,
				TransitionTimestamp: 100,
			},
		},
	}

	ctrl := gomock.NewController(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mock_verification.NewMockBlockchainCaller(ctrl)
			tt.prepareMock(m, t)

			stateResult, err := Verify(context.Background(), m, mockContractAddress, mockGenesisID, mockGenesisState)
			require.Nil(t, err)
			require.Equal(t, tt.expected, stateResult)
		})
	}
	ctrl.Finish()
}

func TestVerifyState_Error(t *testing.T) {
	tests := []struct {
		name        string
		prepareMock func(mbc *mock_verification.MockBlockchainCaller, t *testing.T)
		expected    VerificationResult
		expectedErr error
	}{
		{
			name: "id from block-chain and request not equal",
			prepareMock: func(mbc *mock_verification.MockBlockchainCaller, t *testing.T) {
				// put old state in block-chain.
				args := abi.Arguments{
					{Type: uint256Ty, Name: ""},
				}
				b, err := args.Pack(big.NewInt(100))
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

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
					big.NewInt(100), // ReplacedAtTimestamp
					big.NewInt(0),   // CreatedAtTimestamp
					uint64(0),       // ReplacedAtBlock
					uint64(0),       // CreatedAtBlock
					big.NewInt(1),   // ID
					big.NewInt(0),   // ReplacedBy
				)
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)
			},
			expected:    VerificationResult{},
			expectedErr: errors.New("transition info contains invalid id"),
		},
		{
			name: "no information of transition for non-latest state",
			prepareMock: func(mbc *mock_verification.MockBlockchainCaller, t *testing.T) {
				// put old state in block-chain.
				args := abi.Arguments{
					{Type: uint256Ty, Name: ""},
				}
				b, err := args.Pack(big.NewInt(100))
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)

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
					big.NewInt(0), // ReplacedAtTimestamp
					big.NewInt(0), // CreatedAtTimestamp
					uint64(0),     // ReplacedAtBlock
					uint64(0),     // CreatedAtBlock
					mockGenesisID, // ID
					big.NewInt(0), // ReplacedBy
				)
				require.NoError(t, err)

				mbc.EXPECT().CallContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(b, nil)
			},
			expected:    VerificationResult{},
			expectedErr: errors.New("no information of transition for non-latest state"),
		},
	}

	ctrl := gomock.NewController(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := mock_verification.NewMockBlockchainCaller(ctrl)
			tt.prepareMock(m, t)

			stateResult, err := Verify(context.Background(), m, mockContractAddress, mockGenesisID, mockGenesisState)
			require.NotNil(t, err)
			require.EqualError(t, err, tt.expectedErr.Error())
			require.Equal(t, tt.expected, stateResult)
		})
	}
	ctrl.Finish()
}

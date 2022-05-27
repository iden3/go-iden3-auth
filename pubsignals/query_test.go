package pubsignals

import (
	"math/big"
	"testing"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/assert"
)

func TestVerifyQuery(t *testing.T) {

	cases := []struct {
		Desc   string
		Query  circuits.Query
		Output ClaimOutputs
		Err    string
	}{
		{"NOOP",
			circuits.Query{SlotIndex: 0, Values: nil, Operator: circuits.NOOP},
			ClaimOutputs{SlotIndex: 0, Operator: circuits.NOOP, Value: nil},
			"",
		},
		{"NOOP diff value", // in this case it is ok that slot and value contains different values as we don't care
			// about the values in this case, and do not validate them
			circuits.Query{SlotIndex: 1, Values: []*big.Int{big.NewInt(2)}, Operator: circuits.NOOP},
			ClaimOutputs{SlotIndex: 3, Operator: circuits.NOOP, Value: []*big.Int{big.NewInt(3)}},
			"",
		},
		{"NOOP err",
			circuits.Query{SlotIndex: 1, Values: []*big.Int{big.NewInt(2)}, Operator: circuits.GT},
			ClaimOutputs{SlotIndex: 3, Operator: circuits.NOOP, Value: []*big.Int{big.NewInt(3)}},
			"operator that was used is not equal to requested in query",
		},
		{"Equal values",
			circuits.Query{SlotIndex: 1, Values: []*big.Int{big.NewInt(2)}, Operator: circuits.GT},
			ClaimOutputs{SlotIndex: 1, Operator: circuits.GT, Value: []*big.Int{big.NewInt(2)}},
			"",
		},
		{"Err diff slots",
			circuits.Query{SlotIndex: 1, Values: []*big.Int{big.NewInt(2)}, Operator: circuits.GT},
			ClaimOutputs{SlotIndex: 2, Operator: circuits.GT, Value: []*big.Int{big.NewInt(2)}},
			"wrong claim slot was used in claim",
		},
		{"Err diff values",
			circuits.Query{SlotIndex: 1, Values: []*big.Int{big.NewInt(2)}, Operator: circuits.LT},
			ClaimOutputs{SlotIndex: 1, Operator: circuits.LT, Value: []*big.Int{big.NewInt(3)}},
			"comparison value that was used is not equal to requested in query",
		},
	}

	for _, c := range cases {
		t.Run(c.Desc, func(t *testing.T) {
			got := verifyQuery(c.Query, c.Output)

			if c.Err != "" {
				assert.Errorf(t, got, c.Err)
			} else {
				assert.NoError(t, got)
			}

		})
	}

}

func TestVerifyIssuer(t *testing.T) {
	id, err := core.IDFromString("11QQNY4iC5hkQmcaNFDzgzHhzB6g7i7RGhNwXQhXA")
	assert.NoError(t, err)

	query := Query{AllowedIssuers: []string{"*"}}
	out := ClaimOutputs{IssuerID: &id}
	assert.True(t, verifyIssuer(query, out))

	query = Query{AllowedIssuers: []string{"11QQNY4iC5hkQmcaNFDzgzHhzB6g7i7RGhNwXQhXA"}}
	out = ClaimOutputs{IssuerID: &id}
	assert.True(t, verifyIssuer(query, out))

	query = Query{AllowedIssuers: []string{"112qpwUbRQ8hwFS69X1Piun39Qz9mujuZfdUGLJjTW", "11QQNY4iC5hkQmcaNFDzgzHhzB6g7i7RGhNwXQhXA"}}
	out = ClaimOutputs{IssuerID: &id}
	assert.True(t, verifyIssuer(query, out))

	query = Query{AllowedIssuers: []string{"112qpwUbRQ8hwFS69X1Piun39Qz9mujuZfdUGLJjTW"}}
	out = ClaimOutputs{IssuerID: &id}
	assert.False(t, verifyIssuer(query, out))
}

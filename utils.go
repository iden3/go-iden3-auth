package go_iden3_auth

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
)

// ArrayStringToBigInt converts string array to array of big integers
func ArrayStringToBigInt(s []string) ([]*big.Int, error) {
	var o []*big.Int
	for i := 0; i < len(s); i++ {
		si, err := stringToBigInt(s[i])
		if err != nil {
			return o, nil
		}
		o = append(o, si)
	}
	return o, nil
}

func stringToBigInt(s string) (*big.Int, error) {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("can not parse string to *big.Int: %s", s)
	}
	return n, nil
}

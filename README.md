# go-iden3-auth

[![Go Reference](https://pkg.go.dev/badge/github.com/iden3/go-iden3-auth.svg)](https://pkg.go.dev/github.com/iden3/go-iden3-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-iden3-auth)](https://goreportcard.com/report/github.com/iden3/go-iden3-auth)
[![Test](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-test.yaml/badge.svg)](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-test.yaml)
[![Lint](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-lint.yaml/badge.svg)](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-lint.yaml)

> Library for verification of authorization response messages of communication protocol in JWZ format
>


`go get github.com/iden3/go-iden3-auth`

### General description:

The goal of iden3auth libraries is to handle authentication messages of communication protocol.

Currently, library implementation includes support of next message types

1. `https://iden3-communication.io/authorization/1.0/request`
2. `https://iden3-communication.io/authorization/1.0/response`


---

Auth verification procedure:

1. JWZ token verification
2. Zero-knowledge proof verification of request proofs
3. Query request verification for atomic circuits 
4. Verification of identity and issuer states for atomic circuits

### Zero-knowledge proof verification

> Groth16 proof are supported by auth library
>

Verification keys must be provided using `KeyLoader` interface

### Query verification 

Proof for each atomic circuit contains public signals that allow extracting user and issuer identifiers, states, signature challenges, etc.

Circuit public signals marshallers are defined in the go-circuits library.

### Verification of user / issuer identity states

The blockchain verification algorithm is used

1. Gets state from the blockchain (address of id state contract and URL must be provided by the caller of the library):
  1. Empty state is returned - it means that identity state hasn’t been updated or updated state hasn’t been published. We need to compare id and state. If they are different it’s not a genesis state of identity then it’s not valid.
  2. The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough and we work with the latest user state.
  3. The non-empty state is returned and it’s not equal to the state that the user has provided. Gets the transition time of the state. The verification party can make a decision if it can accept this state based on that time frame

2. Only latest states for user are valid. Any existing issuer state for claim issuance is valid.

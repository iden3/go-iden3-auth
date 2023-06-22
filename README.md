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

Proof for each atomic circuit contains public signals that allow extracting user and issuer identifiers, states, signature, challenges, etc.

Circuit public signals marshallers are defined in the go-circuits library.

### Verification of user / issuer identity states

The blockchain verification algorithm is used

1. Gets state from the blockchain (address of id state contract and URL must be provided by the caller of the library):
   1. Empty state is returned - it means that identity state hasn’t been updated or updated state hasn’t been published. We need to compare id and state. If they are different it’s not a genesis state of identity then it’s not valid.
   2. The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough and we work with the latest user state.
   3. The non-empty state is returned and it’s not equal to the state that the user has provided. Gets the transition time of the state. The verification party can make a decision if it can accept this state based on that time frame.

2. Only latest states for user are valid. Any existing issuer state for claim issuance is valid.

### Verification of GIST

The blockchain verification algorithm is used

1. Get GIST from the blockchain (address of id state contract and URL must be provided by the caller of the library):
   1. A non-empty GIST is returned, equal to the GIST is provided by the user, it means the user is using the latest state.
   2. The non-empty GIST is returned and it’s not equal to the GIST is provided by a user. Gets the transition time of the GIST. The verification party can make a decision if it can accept this state based on that time frame.
## How to use:
1. `go get https://github.com/iden3/go-iden3-auth`
2. Request generation:

   basic auth:
   ``` golang
   var request protocol.AuthorizationRequestMessage
   // if you need'message' to sign (e.g. vote)
   request = auth.CreateAuthorizationRequestWithMessage("test flow", "message to sign","verifier id", "callback url")
   // or if you don't need 'message' to sign
   request = auth.CreateAuthorizationRequest("test flow","verifier id", "callback url")
   ``` 
   if you want request specific proof (example):
   ``` golang
   var mtpProofRequest protocol.ZeroKnowledgeProofRequest
   mtpProofRequest.ID = 1
   mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
   mtpProofRequest.Query = map[string]interface{}{
      "allowedIssuers": []string{"*"},
      "credentialSubject": map[string]interface{}{
         "countryCode": map[string]interface{}{
            "$nin": []int{840, 120, 340, 509},
         },
      },
      "context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
      "type":    "KYCCountryOfResidenceCredential",
   }
   request.Body.Scope = append(request.Body.Scope, mtpProofRequest)       
   ```
3. Token verification

   Init Verifier:
   
   ```go
   var verificationKeyloader = &loaders.FSKeyLoader{Dir: keyDIR}
   resolver := state.ETHResolver{
      RPCUrl:          <polygon_node_http>,
      ContractAddress: <state_contract_address>,
   }

   resolvers := map[string]pubsignals.StateResolver{
      "polygon:mumbai": resolver,
   }
   verifier,err := auth.NewVerifierWithExplicitError(verificationKeyloader, loaders.DefaultSchemaLoader{IpfsURL: "<IPFS NODE HERE>"}, resolvers)
   // or use NewVerifier and check that verifier instance is not nil. IPFS merklization is not worked without setuping global loader
   // verifier := auth.NewVerifier(verificationKeyloader, loaders.DefaultSchemaLoader{IpfsURL: "ipfs.io"}, resolvers)
    ```
4. FullVerify:

   ```go
   authResponse, err := verifier.FullVerify(
      r.Context(), 
      string(tokenBytes),
      authRequest.(protocolAuthorizationRequestMessage), 
      ...VerifyOpt,
   )
   userId = authResponse.from // msg sender
   ``` 

   Verify manually if thread id is used a session id to match request with `VerifyJWZ / VerifyAuthResponse` functions

### Notes on prover optimization for x86_64 hardware

See readme in [iden3/go-rapidsnark/prover](https://github.com/iden3/go-rapidsnark/blob/main/prover/)

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

&copy; 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

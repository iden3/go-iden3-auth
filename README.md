# go-iden3-auth

[![Go Reference](https://pkg.go.dev/badge/github.com/iden3/go-iden3-auth.svg)](https://pkg.go.dev/github.com/iden3/go-iden3-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-iden3-auth)](https://goreportcard.com/report/github.com/iden3/go-iden3-auth)
[![Test](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-test.yaml/badge.svg)](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-test.yaml)
[![Lint](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-lint.yaml/badge.svg)](https://github.com/iden3/go-iden3-auth/actions/workflows/ci-lint.yaml)

> Library for authentication and authorization that is used in the communication protocol
>


`go get github.com/iden3/go-iden3-auth`

### General description:

The goal of iden3auth libraries is to handle authentication messages of communication protocol.

Currently, library implementation includes support of next message types

1. `https://iden3-communication.io/authorization-request/v1`
2. `https://iden3-communication.io/authorization-response/v1`

The library supports the creation of authorization requests with a possibility to request zero-knowledge proofs and signature proofs.

- Example of authorization request:

    ```json
    {
      "type": "https://iden3-communication.io/authorization-request/v1",
      "data": {
        "callbackUrl": "https://test.com",
        "audience": "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
        "scope": [
            {
              "circuit_id": "auth",
              "type": "zeroknowledge",
              "rules": {
                  "audience": "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
                  "challenge": 12345
              }
          }
       ]
      }
    }
    ```

    💡 <br />
    _type_ - represents protocol message kind <br />
    _scope_ is an array of all proof that are requested by verifier<br />
    _audience_ is a verifier identifier or url<br />
    _callbackUrl_  is an URL  where requested party should send a response message<br />


- Sample of authorization request creation

    ```go
    aud := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ" // verifier ID
    zkpProofRequest := types.ZeroKnowledgeProofRequest{ // prepared ZKP request for KYC circuit
    		Type:      types.ZeroKnowledgeProofType,
    		CircuitID: types.KycBySignaturesCircuitID,
    		Rules: map[string]interface{}{
    			"challenge":        12345678,
    			"countryBlacklist": []int{840},
    			"currentYear":      2021,
    			"currentMonth":     9,
    			"currentDay":       28,
    			"minAge":           18,
    			"audience":         aud,
    			"allowedIssuers": []string{
    				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
    				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
    			},
    		},
    	}
    
    	request := CreateAuthorizationRequest("12345", aud, "https://test.com/callback") //creation auth request
    	request.WithZeroKnowledgeProofRequest(zkpProofRequest) // ask for specific proof
    ```


Also, it supports the verification of authorization-response.

- Example of authorization response:

    ```json
  {
  "type": "https://iden3-communication.io/authorization-response/v1",
  "data": {
    "scope": [
      {
        "type": "zeroknowledge",
        "circuit_id": "auth",
        "pub_signals": [
          "371135506535866236563870411357090963344408827476607986362864968105378316288",
          "12345",
          "16751774198505232045539489584666775489135471631443877047826295522719290880931"
        ],
        "proof_data": {
          "pi_a": [
            "8286889681087188684411199510889276918687181609540093440568310458198317956303",
            "20120810686068956496055592376395897424117861934161580256832624025185006492545",
            "1"
          ],
          "pi_b": [
            [
              "8781021494687726640921078755116610543888920881180197598360798979078295904948",
              "19202155147447713148677957576892776380573753514701598304555554559013661311518"
            ],
            [
              "15726655173394887666308034684678118482468533753607200826879522418086507576197",
              "16663572050292231627606042532825469225281493999513959929720171494729819874292"
            ],
            [
              "1",
              "0"
            ]
          ],
          "pi_c": [
            "9723779257940517259310236863517792034982122114581325631102251752415874164616",
            "3242951480985471018890459433562773969741463856458716743271162635077379852479",
            "1"
          ],
          "protocol": "groth16"
        }
      }
    ]
    }
  }
  ```

    💡 <br />
    *proof_data* is groth16 proof <br />
    *pub_signals*  are public inputs of proof that were used by prover <br />
    *circuit_id* is identifier of specific circuit that was used for proof <br />

   

- Sample of authorization response handling

    ```go
    message, err := packer.Unpack(msgBytes) // unpack raw message
    err = auth.VerifyProof(message)  // call to library to verify zkp proofs
    if err != nil {
    		// do smth ...
    }
    token, err := auth.ExtractMetadata(message)
    if err != nil {
    		// do smth ...
    }
    stateInfo, err := token.VerifyState(ctx.Background(),"< rpc url >", "< state contract address >")
    if err != nil {
    		// do smth ...
    }
    log.Infof("user identifier from token %s", token.Identifier) // we can get user id from proofs 
    log.Infof("auth challenge that was %s", token.Challenge) // we can get challenge from proofs 
    log.Infof("any other info from token %+v", token.Scope) // we can get any info according to circuit schemas
    log.Infof("state information latest: %t, transition time: %v", stateInfo.Latest, stateInfo.TransitionTimestamp) // we can get info about state

   ```


Auth library works with plain packer which doesn't support encoding or encryption but it can be implemented by introducing another packer.

- Packer interface

    ```go
    // Packer converts message to encrypted or encoded form
    type Packer interface {
    	// Pack a payload of type ContentType in an Iden3 compliant format using the sender identity
    	Pack(contentType string, payload types.Message) ([]byte, error)
    	// Unpack an envelope in Iden3 compliant format.
    	Unpack(envelope []byte) (*types.Message, error)
    }
    ```

- Sample of plain packer using

    ```go
    
    request := CreateAuthorizationRequest(challenge, aud, "https://test.com/callback") //creation
    
    msgBytes, err := packer.Pack("application/json", &request) // pack any message
    
    message, err := packer.Unpack(msgBytes) // unpack raw message
    
    ```


---

Auth verification procedure:

1. Zero-knowledge proof verification
2. Extraction of metadata: (auth and circuit-specific)
3. Verification of user identity states
4. Verification of claim non-revocation and issuers states

### Zero-knowledge proof verification

> Groth16 proof are supported now by auth library
>

Verification keys for circuits are known by the library itself. In the future, they can be resolved from circuits registries.

### Extraction of metadata

Each circuit has a schema of its public inputs that links the public signal name to its position in the resulted array.

This allows extracting user identifiers and challenges for authentication from proof.

Other signals are added to the user token ( scope field) as attributes of a specific circuit.

Circuit public signals schemas are known by this library or can be retrieved from some registry.

### Verification of user identity states

The blockchain verification algorithm is used

1. Gets state from the blockchain (address of id state contract and URL must be provided by the caller of the library):
  1. Empty state is returned - it means that identity state hasn’t been updated or updated state hasn’t been published. We need to compare id and state. If they are different it’s not a genesis state of identity then it’s not valid.
  2. The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough and we work with the latest user state.
  3. The non-empty state is returned and it’s not equal to the state that the user has provided. Gets the transition time of the state. The verification party can make a decision if it can accept this state based on that time frame

2. Verification party can make a decision to accept or not provided state information

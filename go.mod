module github.com/iden3/go-iden3-auth

go 1.17

replace github.com/iden3/iden3comm => ../iden3comm

require (
	github.com/ethereum/go-ethereum v1.10.15
	github.com/iden3/go-circuits v0.0.33
	github.com/iden3/go-iden3-core v0.0.14
	github.com/iden3/go-merkletree-sql v1.0.0-pre8
	github.com/iden3/go-schema-processor v0.0.19
	github.com/iden3/iden3comm v0.0.1
	github.com/golang/mock v1.3.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
)

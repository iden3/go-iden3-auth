###

#Unit tests
test:
	go test -v -race -count=1 -timeout=60s ./...

lint:
	 golangci-lint --config .golangci.yml run

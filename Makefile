.PHONY: build test integration typescript
build:
	go build -trimpath -o bin/galleton ./cmd/galleton
	go build -trimpath -o bin/demo-provider ./cmd/demo-provider

test: typescript
	go test -race -count=1 -cover ./...
	go vet ./...
	node --test sdk/typescript/test.mjs
	PYTHONPATH=sdk/python python -m unittest discover -s sdk/python -v

integration:
	python tests/integration.py

typescript:
	npx --yes --package typescript@5.8.3 tsc -p sdk/typescript/tsconfig.json

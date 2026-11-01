.PHONY: build run test e2e examples clean

E2E_VENV := tests/e2e/.venv

build:
	go build -o bin/godocan ./cmd/server

run:
	go run ./cmd/server

test:
	go test ./...

$(E2E_VENV): tests/e2e/requirements.txt
	python3 -m venv $(E2E_VENV)
	$(E2E_VENV)/bin/pip install -q -r tests/e2e/requirements.txt
	touch $(E2E_VENV)

# End-to-end tests with can-isotp/udsoncan against a real server on vcan0.
e2e: $(E2E_VENV)
	cd tests/e2e && .venv/bin/python -m pytest -q

# Examples of every service against a running server (make run).
examples: $(E2E_VENV)
	$(E2E_VENV)/bin/python examples/client.py

clean:
	rm -rf bin/

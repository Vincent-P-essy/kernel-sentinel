.PHONY: generate build test race lint benchmark replay docker live-lab clean

generate:
	go generate ./internal/probe

build: generate
	go build -trimpath -ldflags='-s -w' -o bin/kernel-sentinel ./cmd/sentinel
	go build -trimpath -ldflags='-s -w' -o bin/sentinel-benchmark ./cmd/benchmark

test: generate
	go test ./... -coverprofile=coverage.out

race: generate
	go test -race ./...

lint: generate
	gofmt -l . | tee /tmp/kernel-sentinel-gofmt
	test ! -s /tmp/kernel-sentinel-gofmt
	go vet ./...

benchmark: build
	mkdir -p reports
	./bin/sentinel-benchmark -events lab/events/attack-suite.jsonl -truth lab/ground-truth.yaml -rules rules -out reports

replay: build
	./bin/kernel-sentinel -source replay -replay lab/events/attack-suite.jsonl -rules rules -listen 127.0.0.1:8081

docker:
	docker compose up --build

live-lab:
	docker compose -f lab/docker-compose.yml up --build --exit-code-from lab-report

clean:
	rm -rf bin coverage.out reports/*.json reports/*.csv reports/*.md

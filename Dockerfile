FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437 AS build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang llvm ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go generate ./internal/probe \
    && go test ./... \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kernel-sentinel ./cmd/sentinel \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/sentinel-benchmark ./cmd/benchmark

FROM gcr.io/distroless/static-debian12:nonroot@sha256:b7bb25d9f7c31d2bdd1982feb4dafcaf137703c7075dbe2febb41c24212b946f
COPY --from=build /out/kernel-sentinel /usr/local/bin/kernel-sentinel
COPY --from=build /out/sentinel-benchmark /usr/local/bin/sentinel-benchmark
COPY rules /etc/kernel-sentinel/rules
COPY lab/events /opt/kernel-sentinel/events
COPY lab/ground-truth.yaml /opt/kernel-sentinel/ground-truth.yaml
USER nonroot:nonroot
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/kernel-sentinel"]
CMD ["-source", "replay", "-replay", "/opt/kernel-sentinel/events/attack-suite.jsonl", "-rules", "/etc/kernel-sentinel/rules", "-listen", "0.0.0.0:8081"]

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_COMMIT=dev
RUN GOFLAGS=-buildvcs=false CGO_ENABLED=0 GOOS=linux go build -ldflags "-X github.com/Dankular/GameBond.Core/buildinfo.Commit=${GIT_COMMIT}" -o /out/gamebond-native-edge ./cmd/edge

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables tini jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gamebond-native-edge /usr/local/bin/gamebond-native-edge
COPY tools/container-entrypoint.sh /usr/local/bin/container-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/container-entrypoint && chmod 0755 /usr/local/bin/container-entrypoint
ENV GAMEBOND_NATIVE_EDGE=1
EXPOSE 4433/udp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/container-entrypoint"]

# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /workspace

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY main.go ./
COPY pkg/ ./pkg/

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -buildvcs=false \
    -ldflags='-s -w' \
    -trimpath \
    -o /out/cert-manager-alidns-webhook .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ENV HOME=/home/nonroot

COPY --from=build --chown=65532:65532 /out/cert-manager-alidns-webhook /cert-manager-alidns-webhook

USER 65532:65532

ENTRYPOINT ["/cert-manager-alidns-webhook"]

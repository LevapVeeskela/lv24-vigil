# syntax=docker/dockerfile:1
# Vigil security auditor image. Build from the repository root:
#   docker build -t lv24-vigil:local .
#   docker run --rm -v "$PWD:/workspace" lv24-vigil:local scan --path /workspace
#
# The runtime image is distroless/static (no shell, no package manager) and
# runs as the nonroot user. The build stage cross-compiles for TARGETARCH.
#
# Base images are pinned by digest (OpenSSF Pinned-Dependencies). These are
# multi-arch index digests, verified with `docker buildx imagetools inspect`
# (MediaType: application/vnd.oci.image.index.v1+json), so the multi-arch
# cross-compile below still resolves per-platform manifests.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG COMMIT=dev
ARG DATE=unknown
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags "-s -w \
      -X github.com/levapveeskela/lv24-vigil/internal/version.Version=${VERSION} \
      -X github.com/levapveeskela/lv24-vigil/internal/version.Commit=${COMMIT} \
      -X github.com/levapveeskela/lv24-vigil/internal/version.Date=${DATE}" \
    -o /out/vigil ./cmd/vigil

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.source="https://github.com/LevapVeeskela/lv24-vigil" \
      org.opencontainers.image.description="Vigil: security audit for your code, on your own model" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.url="https://github.com/LevapVeeskela/lv24-vigil"

COPY --from=build /out/vigil /usr/local/bin/vigil

WORKDIR /workspace
USER nonroot:nonroot
ENTRYPOINT ["vigil"]
CMD ["help"]

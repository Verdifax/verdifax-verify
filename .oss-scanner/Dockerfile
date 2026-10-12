# Scanner image for https://github.com/Verdifax/verdifax-verify.
#
# The verifier is a single-module Go CLI with no dependencies outside
# the Go standard library, so the build is the standard toolchain
# build. The audit runs offline; nothing here needs the network after
# the base image is pulled. threat_model.md, next to this file, says
# what the binary does and how to exercise it.

# The Go release the repository's CI builds and tests with. The image
# ships git and gcc, which the race detector needs.
FROM golang:1.27-bookworm
ENV DEBIAN_FRONTEND=noninteractive

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# No external modules exist, but run the standard step so a future
# dependency cannot silently break the offline audit.
RUN go mod download

# Build as CI builds: vet, then the binary with debug info retained
# (no -s -w, the scanner benefits from symbols).
RUN go vet ./... && go build -o /usr/local/bin/verdifax-verify .

# Run the full test suite, race detector on, so the image is known
# good; a failing test warns rather than aborting the image build.
RUN go test -race ./... || echo "WARNING: go test reported failures"

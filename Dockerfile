# lockhub in Docker: the hub runs in this image (lockhub serve), and the
# `lock` CLI is shipped in it too, so a release is one signed image.
#
#   lockhub (uid 10040)  the hub account; its state lives in /var/lib/lockhub
#
# The container is meant to run read-only (--read-only, --cap-drop ALL),
# with a named volume on /var/lib/lockhub.
#
#   docker build -t lockhub .
#
# The base images are pinned by digest: update the tag and the digest
# together (docker buildx imagetools inspect golang:1.26-alpine).

FROM golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# VERSION: the release version without its "v" (0.1.0).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/lockhub ./cmd/lockhub \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/lock ./cmd/lock

FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
RUN addgroup -S -g 10040 lockhub \
 && adduser -S -D -H -u 10040 -G lockhub -s /sbin/nologin -g "lockhub" lockhub \
 && install -d -m 0700 -o lockhub -g lockhub /var/lib/lockhub
COPY --from=build --chown=root:root --chmod=0755 /out/lockhub /usr/local/bin/lockhub
COPY --from=build --chown=root:root --chmod=0755 /out/lock /usr/local/bin/lock

# A named volume takes this directory's owner and mode on first use.
VOLUME ["/var/lib/lockhub"]
WORKDIR /var/lib/lockhub
USER lockhub
EXPOSE 8443
ENTRYPOINT ["lockhub"]
CMD ["serve"]

# Rebuild gosu with the patched local Go toolchain instead of shipping the
# older gosu binary bundled in the upstream Redis image.
FROM golang:1.26.9-bookworm AS gosu-builder

ENV GOTOOLCHAIN=local
RUN go install github.com/tianon/gosu@latest

FROM redis:7.4.11-bookworm
COPY --from=gosu-builder /go/bin/gosu /usr/local/bin/gosu

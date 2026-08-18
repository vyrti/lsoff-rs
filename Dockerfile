# Multi-stage build for minimal lsoff-rs container
FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY . .

RUN cargo build --release --bin lsoff-rs

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/lsoff-rs /usr/local/bin/lsoff-rs

ENTRYPOINT ["/usr/local/bin/lsoff-rs"]
CMD []

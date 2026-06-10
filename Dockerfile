# Static musl build -> scratch. No *dynamic* deps, no runtime — TLS is rustls
# (no OpenSSL) and SQLite is the statically-compiled bundled amalgamation (gcc
# below exists only to build it): the final image is just the binary, a few MB.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release && strip -s target/release/sql-mcp

FROM scratch
COPY --from=build /src/target/release/sql-mcp /sql-mcp
# Config is mounted at runtime, e.g.:
#   docker run --rm -i -v $PWD/sql-mcp.toml:/sql-mcp.toml:ro sql-mcp
ENTRYPOINT ["/sql-mcp"]

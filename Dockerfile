FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release && strip -s target/release/sql-mcp

FROM scratch
COPY --from=build /src/target/release/sql-mcp /sql-mcp
ENTRYPOINT ["/sql-mcp"]

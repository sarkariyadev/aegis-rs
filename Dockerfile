FROM rust:1.82-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/aegis-rs /usr/local/bin/aegis-rs
CMD ["aegis-rs"]

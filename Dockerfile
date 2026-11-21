# megaquarry CLI image. Build it on the machine that runs it (on an
# Apple Silicon Mac this gives an arm64 image): `docker compose build`.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p megaquarry-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home megaquarry
COPY --from=build /src/target/release/megaquarry /usr/local/bin/megaquarry
# Unprivileged and without NET_ADMIN: the VPN belongs to the `vpn` service.
USER 1000
ENV MEGAQUARRY_HOME=/data
# Downloads land in the working directory (`default_down_dir` is `.`).
WORKDIR /downloads
ENTRYPOINT ["megaquarry"]

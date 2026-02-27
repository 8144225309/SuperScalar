FROM ubuntu:24.04

# Build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git libsqlite3-dev ca-certificates \
    autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Bitcoin Core 28.1 (regtest only)
RUN apt-get update && apt-get install -y --no-install-recommends wget && \
    wget -q https://bitcoincore.org/bin/bitcoin-core-28.1/bitcoin-28.1-x86_64-linux-gnu.tar.gz && \
    tar xzf bitcoin-28.1-x86_64-linux-gnu.tar.gz && \
    install -m 0755 bitcoin-28.1/bin/bitcoind bitcoin-28.1/bin/bitcoin-cli /usr/local/bin/ && \
    rm -rf bitcoin-28.1* && \
    apt-get purge -y wget && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy source and build
WORKDIR /superscalar
COPY . .
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Entrypoint: start bitcoind regtest, fund wallet, run demo
COPY tools/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["demo"]

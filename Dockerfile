FROM ubuntu:24.04

# Build deps + python3 for integration tests
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git libsqlite3-dev libssl-dev ca-certificates \
    autoconf automake libtool pkg-config python3 procps \
    && rm -rf /var/lib/apt/lists/*

# Bitcoin Core 28.1 (regtest only)
RUN apt-get update && apt-get install -y --no-install-recommends wget && \
    wget -q https://bitcoincore.org/bin/bitcoin-core-28.1/bitcoin-28.1-x86_64-linux-gnu.tar.gz && \
    tar xzf bitcoin-28.1-x86_64-linux-gnu.tar.gz && \
    install -m 0755 bitcoin-28.1/bin/bitcoind bitcoin-28.1/bin/bitcoin-cli /usr/local/bin/ && \
    rm -rf bitcoin-28.1* && \
    apt-get purge -y wget && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Bitcoin regtest config with RPC auth (matches test scripts)
RUN mkdir -p /root/.bitcoin && printf '\
regtest=1\n\
server=1\n\
rpcuser=rpcuser\n\
rpcpassword=rpcpass\n\
fallbackfee=0.00001\n\
txindex=1\n\
[regtest]\n\
rpcport=18443\n\
' > /root/.bitcoin/bitcoin.conf

# Copy source and build
WORKDIR /superscalar
COPY . .
# Fix Windows CRLF line endings in scripts (common when developing on Windows)
RUN find . -name '*.sh' -o -name '*.py' | xargs sed -i 's/\r$//'
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Entrypoint: start bitcoind regtest, fund wallet, run demo
COPY tools/docker-entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["demo"]

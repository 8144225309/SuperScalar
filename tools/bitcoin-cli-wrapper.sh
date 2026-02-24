#!/bin/bash
# Wrapper to invoke bitcoin-cli from PATH.
# Override by setting BITCOIN_CLI_PATH in your environment.
exec "${BITCOIN_CLI_PATH:-bitcoin-cli}" "$@"

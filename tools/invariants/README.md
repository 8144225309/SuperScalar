# On-chain invariant checker

`check_chain.py` checks a finished regtest drill against the chain. It reads
the node over JSON-RPC (no `-txindex` needed) and the LSP's and members'
SQLite databases, read-only. It needs only Python 3.

| Check | What must hold |
|---|---|
| `conservation` | From each factory funding outpoint, every sat ends in a terminal output or a fee. Every fee is within `--max-feerate`. No output of a transaction that no database signed beforehand pays a script that no party owns. |
| `balances` | A confirmed commitment is the member's latest. It pays to_local and to_remote exactly as the member's database says, less the 240 sat anchor taken from to_remote. The LSP's commitment pays the member its balance. The distribution TX pays each member at least its channel capacity and pays only members. The LSP's and member's databases agree at the same commitment number. |
| `revocation` | A confirmed revoked commitment has its to_local taken by the penalty, not left unspent or swept by the CSV path. A commitment is revoked when the other side's database holds its per-commitment secret. |
| `exit` | A member that has not exited can still exit from its own database. Its commitment and every unconfirmed ancestor are stored, none conflicts with the chain, and every key-path signature on the path verifies. The node accepts the first one, apart from relay-fee and timelock refusals. Failing that, its distribution TX must still be spendable. |

A party owns an output when the output pays one of the following:

- a participant key, key path only
- a commitment to_remote derived from the databases
- an address of a node wallet given with `--wallet`
- a P2A anchor
- a script passed with `--allow-spk`

```
tools/invariants/check_chain.py --conf "$REGTEST_CONF" --db-dir DRILL_DIR --wallet WALLET
tools/invariants/check_chain.py --rpcport 18443 --rpcuser U --rpcpassword P \
    --lsp-db lsp.db --member-db c0.db --member-db c1.db [--checks exit,revocation]
```

With `--db-dir`, the checker reads `lsp.db` and `c<N>.db` from that
directory. It writes a JSON report to stdout, or to the file given with
`--json`. The summary and any violations go to stderr. It exits 0 when every
check passes, 1 on a violation, and 2 on a usage or RPC error.

## In the scenario scripts

The following scripts source `hook.sh` and run the checker at the end of each
drill:

- `test_regtest_advanceless.sh`
- `test_regtest_client_exit_without_lsp.sh`
- `test_regtest_tree_exit.sh`

A violation fails the scenario. The report is written to
`invariants.json` in the drill directory. Set `SS_CHECK_INVARIANTS=0` to skip
the check.

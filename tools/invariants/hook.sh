# hook.sh -- sourced by the regtest scenario scripts to check the on-chain
# invariants (check_chain.py) at the end of a drill.
#
#   ss_invariants_on                  true unless SS_CHECK_INVARIANTS=0
#   ss_check_invariants DIR ARGS...   run check_chain.py on the databases in
#                                     DIR (lsp.db, c*.db) with the node and
#                                     wallet arguments ARGS; the JSON report
#                                     goes to DIR/invariants.json, violations
#                                     and the summary to stdout; returns
#                                     its exit status
SS_INVARIANTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ss_invariants_on() { [ "${SS_CHECK_INVARIANTS:-1}" != 0 ]; }
ss_check_invariants() {
    local d=$1
    shift
    python3 "$SS_INVARIANTS_DIR/check_chain.py" --db-dir "$d" --quiet \
        --json "$d/invariants.json" "$@" 2>&1
}

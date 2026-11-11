#ifndef SUPERSCALAR_NETWORK_H
#define SUPERSCALAR_NETWORK_H

#include <stddef.h>

/*
 * Chain names and the mainnet start-up gates.
 *
 * The chain is selected by name ("regtest", "signet", "testnet", "testnet4",
 * "mainnet").  "bitcoin" is accepted as another spelling of "mainnet".  Every
 * decision that depends on the chain being mainnet goes through
 * network_is_mainnet(), so both spellings always get the same treatment.
 */

/* 1 if network names Bitcoin mainnet ("mainnet" or "bitcoin"), else 0. */
int network_is_mainnet(const char *network);

/* The canonical name of a supported chain: "bitcoin" maps to "mainnet", the
   other supported names map to themselves.  Returns a static string, or NULL
   if network is NULL or not a supported chain.  The daemons canonicalise
   --network once at start-up and use the result everywhere. */
const char *network_canonical(const char *network);

/*
 * Start-up check for a daemon: the one call each daemon makes with what it
 * parsed from its command line.  It refuses a chain name that is not
 * supported and applies every mainnet gate that belongs to the daemon's role:
 *
 *   LSP         risk acknowledgement, no --seckey, no test scaffolding,
 *               --db, --wt-db
 *   client      risk acknowledgement, no --seckey, no test scaffolding, --db
 *   watchtower  risk acknowledgement, no test scaffolding
 *
 * Returns 1 if start-up may continue.  Returns 0 if it must be refused, with
 * a message for the operator in err_buf.
 */
typedef enum {
    NETWORK_ROLE_LSP = 0,
    NETWORK_ROLE_CLIENT,
    NETWORK_ROLE_WATCHTOWER
} network_role_t;

typedef struct {
    network_role_t role;
    const char *network;      /* --network, canonical or not */
    int accept_risk;          /* --i-accept-the-risk given */
    int seckey_on_cmdline;    /* --seckey given */
    int have_db;              /* --db given */
    int have_wt_db;           /* --wt-db given */
    int argc;                 /* the daemon's own argc/argv */
    char *const *argv;
    char *const *envp;        /* its environment (NULL-terminated), or NULL */
} network_startup_t;

int network_startup_gates(const network_startup_t *startup,
                          char *err_buf, size_t err_buf_len);

/*
 * The individual mainnet gates.  Each returns 1 if start-up may continue and 0 if
 * it must be refused, in which case a message for the operator is written to
 * err_buf.  All of them pass on every chain other than mainnet.
 */

/* Mainnet needs the operator's explicit acknowledgement of the risk. */
int network_gate_risk_accepted(const char *network, int accept_risk,
                               char *err_buf, size_t err_buf_len);

/* A secret key on the command line is visible to other local users and is
   kept in shell history: refused on mainnet. */
int network_gate_cmdline_seckey(const char *network, int seckey_on_cmdline,
                                char *err_buf, size_t err_buf_len);

/* Test and fault-injection knobs are refused on mainnet: --cheat-* / --test-*
   arguments in argv[1..argc-1], and SS_CHEAT*, SS_KILL* and SUPERSCALAR_CRASH*
   variables in the NULL-terminated environment envp (may be NULL). */
int network_gate_no_test_scaffolding(const char *network,
                                     int argc, char *const *argv,
                                     char *const *envp,
                                     char *err_buf, size_t err_buf_len);

/* Mainnet needs a database, or revocation secrets do not survive a crash. */
int network_gate_db(const char *network, int have_db,
                    char *err_buf, size_t err_buf_len);

/* A mainnet LSP needs the watchtower database. */
int network_gate_watchtower_db(const char *network, int have_wt_db,
                               char *err_buf, size_t err_buf_len);

#endif /* SUPERSCALAR_NETWORK_H */

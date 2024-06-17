#!/bin/sh
set -ex

# Usage: run_e2e_test.sh <--operators_enabled>

export OPERATORS_ENABLED=false
if [ "$1" = "--operators_enabled" ]; then
    OPERATORS_ENABLED=true
fi

echo "OPERATORS_ENABLED: $OPERATORS_ENABLED"

LCP_BIN=./bin/lcp
ENCLAVE_PATH=./bin/enclave.signed.so
CERTS_DIR=./lcp/tests/certs

export LCP_ENCLAVE_DEBUG=1

./scripts/init_lcp.sh

if [ "$SGX_MODE" = "SW" ]; then
    export LCP_RA_ROOT_CERT_HEX=$(cat ${CERTS_DIR}/root.crt | xxd -p -c 1000000)
fi

./tests/e2e/scripts/gen_rly_config.sh

${LCP_BIN} --log_level=info service start --enclave=${ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
LCP_PID=$!

make -C tests/e2e/cases/tm2tm network
sleep 3
make -C tests/e2e/cases/tm2tm setup handshake

# test for restore ELC state
kill $LCP_PID
./scripts/init_lcp.sh
${LCP_BIN} --log_level=info service start --enclave=${ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
LCP_PID=$!
make -C tests/e2e/cases/tm2tm restore

make -C tests/e2e/cases/tm2tm test-relay
make -C tests/e2e/cases/tm2tm test-elc-cmd
if [ "$OPERATORS_ENABLED" = true ]; then
    make -C tests/e2e/cases/tm2tm test-operators
fi
make -C tests/e2e/cases/tm2tm network-down
kill $LCP_PID

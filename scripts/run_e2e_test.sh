#!/bin/sh
set -ex

LCP_BIN=./bin/lcp
ENCLAVE_PATH=./bin/enclave.signed.so
CERTS_DIR=./lcp/tests/certs

rm -rf ~/.lcp

enclave_key=$(${LCP_BIN} --log_level=off enclave generate-key --enclave=${ENCLAVE_PATH})
./tests/e2e/scripts/gen_rly_config.sh

if [ -z "$SGX_MODE" -o "$SGX_MODE" = "HW" ]; then
    ./bin/lcp attestation ias --enclave=${ENCLAVE_PATH} --enclave_key=${enclave_key}
else
    ./bin/lcp attestation simulate --enclave=${ENCLAVE_PATH} --enclave_key=${enclave_key} --signing_cert_path=${CERTS_DIR}/signing.crt.der --signing_key=${CERTS_DIR}/signing.key
    export LCP_RA_ROOT_CERT_HEX=$(cat ${CERTS_DIR}/root.crt | xxd -p -c 1000000)
fi

./bin/lcp --log_level=info service start --enclave=${ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
LCP_PID=$!

make -C tests/e2e/cases/tm2tm network
sleep 3
make -C tests/e2e/cases/tm2tm test
make -C tests/e2e/cases/tm2tm network-down
kill $LCP_PID

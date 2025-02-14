#!/bin/sh
set -ex

# Usage: run_e2e_test.sh <--operators_enabled> <--no_run_lcp> <--zkdcap>

E2E_TEST_DIR=./tests/e2e/cases/tm2tm
OPERATORS_ENABLED=false
NO_RUN_LCP=false
ZKDCAP=false
ARGS=$(getopt -o '' --long operators_enabled,no_run_lcp,zkdcap -n 'parse-options' -- "$@")
eval set -- "$ARGS"
while true; do
    case "$1" in
        --operators_enabled)
            echo "Operators enabled"
            OPERATORS_ENABLED=true
            shift
            ;;
        --no_run_lcp)
            echo "Skip running LCP"
            if [ "$LCP_MRENCLAVE" = "" ]; then
                echo "LCP_MRENCLAVE is not set"
                exit 1
            fi
            NO_RUN_LCP=true
            shift
            ;;
        --zkdcap)
            echo "ZKDCAP enabled"
            ZKDCAP=true
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Internal error!"
            exit 1
            ;;
    esac
done

if [ "$NO_RUN_LCP" = "false" ]; then
    echo "Run LCP for testing"
    LCP_BIN=${LCP_BIN:-./bin/lcp}
    LCP_ENCLAVE_PATH=${LCP_ENCLAVE_PATH:-./bin/enclave.signed.so}
    export LCP_ENCLAVE_DEBUG=1
    export LCP_MRENCLAVE=$(${LCP_BIN} enclave metadata --enclave=${LCP_ENCLAVE_PATH} | jq -r .mrenclave)
    LCP_BIN=${LCP_BIN} LCP_ENCLAVE_PATH=${LCP_ENCLAVE_PATH} ZKDCAP=${ZKDCAP} ./scripts/init_lcp.sh
    ${LCP_BIN} --log_level=info service start --enclave=${LCP_ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
    LCP_PID=$!
    if [ "$SGX_MODE" = "SW" ]; then
        export LCP_RA_ROOT_CERT_HEX=$(cat ./lcp/tests/certs/root.crt | xxd -p -c 1000000)
        export LCP_DCAP_RA_ROOT_CERT_HEX=$(cat ./dcap_root_cert.pem | xxd -p -c 1000000)
    fi
else
    echo "Skip running LCP"
    echo "We assume that LCP is running with the HW mode"
    if [ "$LCP_MRENCLAVE" = "" ]; then
        echo "LCP_MRENCLAVE is not set"
        exit 1
    fi
fi

ZKDCAP=${ZKDCAP} E2E_TEST_DIR=${E2E_TEST_DIR} OPERATORS_ENABLED=${OPERATORS_ENABLED} ./tests/e2e/scripts/gen_rly_config.sh

make -C ${E2E_TEST_DIR} network
sleep 3
make -C ${E2E_TEST_DIR} setup handshake

if [ "$ZKDCAP" = "false" ] && [ "$NO_RUN_LCP" = "false" ]; then
    echo "Shutdown LCP for testing restore ELC state"
    kill $LCP_PID
    ZKDCAP=${ZKDCAP} ./scripts/init_lcp.sh
    ${LCP_BIN} --log_level=info service start --enclave=${LCP_ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
    LCP_PID=$!
    echo "Restore ELC state"
    make -C ${E2E_TEST_DIR} restore
fi

make -C ${E2E_TEST_DIR} test-relay
make -C ${E2E_TEST_DIR} test-elc-cmd
if [ "$OPERATORS_ENABLED" = "true" ]; then
    make -C ${E2E_TEST_DIR} test-operators
fi
make -C ${E2E_TEST_DIR} network-down
if [ "$NO_RUN_LCP" = false ]; then
    kill $LCP_PID
fi

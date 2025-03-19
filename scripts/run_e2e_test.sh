#!/bin/sh
set -ex

# Usage: run_e2e_test.sh <--no_run_lcp> <--enclave_debug> <--operators_enabled> <--zkdcap> <--mock_zkdcap> <--key_expiration=<integer>>

E2E_TEST_DIR=./tests/e2e/cases/tm2tm
OPERATORS_ENABLED=false
NO_RUN_LCP=false
export LCP_ENCLAVE_DEBUG=0
export LCP_KEY_EXPIRATION=86400
# LCP_RISC0_IMAGE_ID must be set to the same value as in the LCP service
LCP_RISC0_IMAGE_ID=${LCP_RISC0_IMAGE_ID:-0x7238627eef5fe9a95d8cadd1a74c3bb1f703cf312699ce93f4c8aa448f122e6f}
export ZKDCAP=false
export LCP_ZKDCAP_RISC0_MOCK=false
export LCP_RISC0_IMAGE_ID
ARGS=$(getopt -o '' --long no_run_lcp,enclave_debug,operators_enabled,zkdcap,mock_zkdcap,key_expiration: -- "$@")
eval set -- "$ARGS"
while true; do
    case "$1" in
        --no_run_lcp)
            echo "Skip running LCP"
            NO_RUN_LCP=true
            shift
            ;;
        --enclave_debug)
            echo "Enclave debug enabled"
            LCP_ENCLAVE_DEBUG=1
            shift
            ;;
        --operators_enabled)
            echo "Operators enabled"
            OPERATORS_ENABLED=true
            shift
            ;;
        --zkdcap)
            echo "ZKDCAP enabled"
            ZKDCAP=true
            LCP_ZKDCAP_RISC0_MOCK=false
            shift
            ;;
        --mock_zkdcap)
            echo "Mock ZKDCAP enabled"
            ZKDCAP=true
            LCP_ZKDCAP_RISC0_MOCK=true
            shift
            ;;
        --key_expiration)
            echo "Key expiration: $2"
            LCP_KEY_EXPIRATION=$2
            shift 2
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
    export LCP_MRENCLAVE=$(${LCP_BIN} enclave metadata --enclave=${LCP_ENCLAVE_PATH} | jq -r .mrenclave)
    echo "Remove existing LCP configuration"
    rm -rf ~/.lcp
    LCP_BIN=${LCP_BIN} LCP_ENCLAVE_PATH=${LCP_ENCLAVE_PATH} ./scripts/init_lcp.sh
    ${LCP_BIN} --log_level=info service start --enclave=${LCP_ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
    LCP_PID=$!
    if [ "$SGX_MODE" = "SW" ]; then
        export LCP_RA_ROOT_CERT_HEX=$(cat ./lcp/tests/certs/root.crt | xxd -p -c 1000000)
        export LCP_DCAP_RA_ROOT_CERT_HEX=$(cat ./tests/e2e/certs/simulate_dcap_root_cert.pem | xxd -p -c 1000000)
    fi
else
    echo "Skip running LCP"
    echo "We assume that LCP is running with the HW mode"
    res=$(grpcurl -plaintext 127.0.0.1:50051 lcp.service.enclave.v1.Query.EnclaveInfo)
    enclave_debug=$(echo $res | jq -r .enclaveDebug)
    if [ "$enclave_debug" == "true" ]; then
        if [ "$LCP_ENCLAVE_DEBUG" == "0" ]; then
            echo "Remote LCP's enclave debug is enabled, but LCP_ENCLAVE_DEBUG is not set"
            exit 1
        fi
    else
        if [ "$LCP_ENCLAVE_DEBUG" == "1" ]; then
            echo "Remote LCP's enclave debug is disabled, but LCP_ENCLAVE_DEBUG is set"
            exit 1
        fi
    fi
    export LCP_MRENCLAVE=0x$(echo $res | jq -r .mrenclave | base64 -d | xxd -p | tr -d $'\n')
fi

E2E_TEST_DIR=${E2E_TEST_DIR} OPERATORS_ENABLED=${OPERATORS_ENABLED} ./tests/e2e/scripts/gen_rly_config.sh

make -C ${E2E_TEST_DIR} network
sleep 3
make -C ${E2E_TEST_DIR} setup handshake

if [ "$NO_RUN_LCP" = "false" ]; then
    echo "Shutdown LCP for testing restore ELC state"
    kill $LCP_PID
    echo "Remove existing LCP configuration"
    rm -rf ~/.lcp
    ./scripts/init_lcp.sh
    ${LCP_BIN} --log_level=info service start --enclave=${LCP_ENCLAVE_PATH} --address=127.0.0.1:50051 --threads=2 &
    LCP_PID=$!
    echo "Restore ELC state"
    make -C ${E2E_TEST_DIR} restore
fi

# # Run the test 10 times to check if EK rotation works if the current EK is expired
# for i in $(seq 1 10); do
#     echo "Loop: $i"
#     ./scripts/init_lcp.sh
#     make -C ${E2E_TEST_DIR} test-relay
# done

make -C ${E2E_TEST_DIR} test-elc-cmd
if [ "$OPERATORS_ENABLED" = "true" ]; then
    make -C ${E2E_TEST_DIR} test-operators
fi
make -C ${E2E_TEST_DIR} network-down
if [ "$NO_RUN_LCP" = false ]; then
    kill $LCP_PID
fi

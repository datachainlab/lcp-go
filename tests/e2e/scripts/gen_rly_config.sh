#!/bin/bash
set -ex

IS_DEBUG_ENCLAVE=false
if [ "$LCP_ENCLAVE_DEBUG" = "1" ]; then
    IS_DEBUG_ENCLAVE=true
fi
if [ -z "$LCP_KEY_EXPIRATION" ]; then
    echo "LCP_KEY_EXPIRATION is not set"
    exit 1
fi
# set LCP_ZKDCAP_RISC0_MOCK as false if not set
if [ -z "$LCP_ZKDCAP_RISC0_MOCK" ]; then
    LCP_ZKDCAP_RISC0_MOCK=false
fi

TEMPLATE_DIR=${E2E_TEST_DIR}/configs/templates
CONFIG_DIR=${E2E_TEST_DIR}/configs/demo

mkdir -p $CONFIG_DIR
if [ "$ZKDCAP" = true ]; then
    if [ -z "$LCP_RISC0_IMAGE_ID" ]; then
        echo "LCP_RISC0_IMAGE_ID is not set"
        exit 1
    fi

    if [ "$OPERATORS_ENABLED" = true ]; then
        IBC0=ibc-0-zkdcap-operators.json
        IBC1=ibc-1-zkdcap-operators.json
    else
        IBC0=ibc-0-zkdcap.json
        IBC1=ibc-1-zkdcap.json
    fi
    for t in $IBC0 $IBC1; do
        jq -n \
            --arg MRENCLAVE ${LCP_MRENCLAVE} \
            --argjson IS_DEBUG_ENCLAVE ${IS_DEBUG_ENCLAVE} \
            --argjson LCP_KEY_EXPIRATION ${LCP_KEY_EXPIRATION} \
            --arg RISC0_IMAGE_ID ${LCP_RISC0_IMAGE_ID} \
            --argjson LCP_ZKDCAP_RISC0_MOCK ${LCP_ZKDCAP_RISC0_MOCK} \
            -f ${TEMPLATE_DIR}/$t.tpl > ${CONFIG_DIR}/${t:0:5}.json
    done
else
    if [ "$OPERATORS_ENABLED" = true ]; then
        IBC0=ibc-0-operators.json
        IBC1=ibc-1-operators.json
    else
        IBC0=ibc-0.json
        IBC1=ibc-1.json
    fi
    for t in $IBC0 $IBC1; do
        jq -n \
            --arg MRENCLAVE ${LCP_MRENCLAVE} \
            --argjson IS_DEBUG_ENCLAVE ${IS_DEBUG_ENCLAVE} \
            --argjson LCP_KEY_EXPIRATION ${LCP_KEY_EXPIRATION} \
            -f ${TEMPLATE_DIR}/$t.tpl > ${CONFIG_DIR}/${t:0:5}.json
    done
fi

#!/bin/bash
set -ex

IS_DEBUG_ENCLAVE=false
if [ "$LCP_ENCLAVE_DEBUG" = "1" ]; then
    IS_DEBUG_ENCLAVE=true
fi

TEMPLATE_DIR=${E2E_TEST_DIR}/configs/templates
CONFIG_DIR=${E2E_TEST_DIR}/configs/demo

mkdir -p $CONFIG_DIR
if [ "$ZKDCAP" = true ]; then
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
            --arg RISC0_IMAGE_ID ${LCP_RISC0_IMAGE_ID} \
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
            -f ${TEMPLATE_DIR}/$t.tpl > ${CONFIG_DIR}/${t:0:5}.json
    done
fi

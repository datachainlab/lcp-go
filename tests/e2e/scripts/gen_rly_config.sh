#!/bin/sh
set -eux
TEMPLATE_DIR=./tests/e2e/cases/tm2tm/configs/templates
CONFIG_DIR=./tests/e2e/cases/tm2tm/configs/demo

if [ "$OPERATORS_ENABLED" = true ]; then
    IBC_0_TEMPLATE=ibc-0-operators.json.tpl
    IBC_1_TEMPLATE=ibc-1-operators.json.tpl
else
    IBC_0_TEMPLATE=ibc-0.json.tpl
    IBC_1_TEMPLATE=ibc-1.json.tpl
fi

mkdir -p $CONFIG_DIR
MRENCLAVE=$(./bin/lcp enclave metadata --enclave=./bin/enclave.signed.so | jq -r .mrenclave)
jq --arg MRENCLAVE ${MRENCLAVE} -r '.prover.mrenclave = $MRENCLAVE' ${TEMPLATE_DIR}/$IBC_0_TEMPLATE > ${CONFIG_DIR}/ibc-0.json
jq --arg MRENCLAVE ${MRENCLAVE} -r '.prover.mrenclave = $MRENCLAVE' ${TEMPLATE_DIR}/$IBC_1_TEMPLATE > ${CONFIG_DIR}/ibc-1.json

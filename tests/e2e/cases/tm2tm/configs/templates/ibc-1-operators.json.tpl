{
  "chain": {
    "@type": "/relayer.chains.tendermint.config.ChainConfig",
    "key": "testkey",
    "chain_id": "ibc1",
    "rpc_addr": "http://localhost:26557",
    "account_prefix": "cosmos",
    "gas_adjustment": 1.5,
    "gas_prices": "0.025stake",
    "average_block_time_msec": 1000,
    "max_retry_for_commit": 5
  },
  "prover": {
    "@type": "/relayer.provers.lcp.config.ProverConfig",
    "origin_prover": {
      "@type": "/relayer.chains.tendermint.config.ProverConfig",
      "trusting_period": "336h",
      "refresh_threshold_rate": {
        "numerator": 1,
        "denominator": 2
      }
    },
    "lcp_service_address": "localhost:50051",
    "mrenclave": $MRENCLAVE,
    "allowed_quote_statuses": ["SWHardeningNeeded"],
    "allowed_advisory_ids": ["INTEL-SA-00219","INTEL-SA-00289","INTEL-SA-00334","INTEL-SA-00477","INTEL-SA-00614","INTEL-SA-00615","INTEL-SA-00617"],
    "key_expiration": 604800,
    "key_update_buffer_time": 0,
    "elc_client_id": "07-tendermint-0",
    "is_debug_enclave": $IS_DEBUG_ENCLAVE,
    "operators": [
      "0x9722414d09f43fb02235d739B50F4C027F43e657"
    ],
    "operators_eip712_cosmos_chain_params": {
      "chain_id": "ibc0",
      "prefix": "ibc"
    },
    "operator_signer": {
      "@type": "/relayer.provers.lcp.signers.raw.SignerConfig",
      "private_key": "0x8a94e9f944a297c402a997aa9a60026ce47a6e018192d111c1703176bbc26651"
    }
  }
}

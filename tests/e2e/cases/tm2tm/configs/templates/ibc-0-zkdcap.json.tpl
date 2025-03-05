{
  "chain": {
    "@type": "/relayer.chains.tendermint.config.ChainConfig",
    "key": "testkey",
    "chain_id": "ibc0",
    "rpc_addr": "http://localhost:26657",
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
    "elc_client_id": "07-tendermint-1",
    "is_debug_enclave": $IS_DEBUG_ENCLAVE,
    "current_tcb_evaluation_data_number": 1,
    "tcb_evaluation_data_number_update_grace_period": 0,
    "risc0_zkvm_config": {
      "image_id": $RISC0_IMAGE_ID,
      "mock": $LCP_ZKDCAP_RISC0_MOCK
    }
  }
}

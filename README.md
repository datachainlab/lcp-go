# lcp-go

lcp-go includes the followings:
- LCP client for ibc-go
- A prover module for yui-relayer
- E2E test between two tendermint chains using yui-relayer

## Dependencies

- [lcp v0.2.17](https://github.com/datachainlab/lcp/releases/tag/v0.2.17)
- [ibc-go v8.2](https://github.com/cosmos/ibc-go/releases/tag/v8.2.0)
- [yui-relayer v0.5.16](https://github.com/hyperledger-labs/yui-relayer/releases/tag/v0.5.16)

## How to run tests

First, you need to build the tendermint images for e2e-test

```bash
$ make tendermint-images
```

Then, run the following command to run e2e test

```bash
$ make e2e-test
```

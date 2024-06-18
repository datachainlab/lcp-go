package main

import (
	"log"

	lcp "github.com/datachainlab/lcp-go/relay"
	"github.com/datachainlab/lcp-go/relay/signers/raw"
	lcptm "github.com/datachainlab/lcp-go/relay/tendermint"
	tendermint "github.com/hyperledger-labs/yui-relayer/chains/tendermint/module"
	"github.com/hyperledger-labs/yui-relayer/cmd"
)

func main() {
	if err := cmd.Execute(
		tendermint.Module{},
		lcp.Module{},
		lcptm.Module{},
		raw.Module{},
	); err != nil {
		log.Fatal(err)
	}
}

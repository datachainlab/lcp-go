package relay

import (
	"context"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/hyperledger-labs/yui-relayer/log"
)

func updateClient(ctx context.Context, client LCPServiceClient, anyHeader *types.Any, elcClientID string, includeState bool, signer []byte) (*elc.MsgUpdateClientResponse, error) {
	stream, err := client.StreamingUpdateClient(ctx)
	if err != nil {
		return nil, err
	}
	chunks := split(anyHeader.Value, 3*1024*1024)
	for i, chunk := range chunks {
		err = stream.Send(&elc.MsgUpdateClient{
			ClientId: elcClientID,
			Header: &types.Any{
				TypeUrl: anyHeader.TypeUrl,
				Value:   chunk,
			},
			IncludeState: includeState,
			Signer:       signer,
		})
		if err != nil {
			log.GetLogger().Error(fmt.Sprintf("chunk failed: index = %d", i), err)
			return nil, err
		}
	}
	return stream.CloseAndRecv()
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

package updater

import (
	"context"
	"fmt"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

// UpdateClientResult represents the result of updateClient operation
type UpdateClientResult struct {
	Message   []byte
	Signature []byte
}

// SetupHeadersForUpdate0 performs the initial setup and updateClient calls
// Returns the processed updateClient results for aggregation
func (pr *Prover) SetupHeadersForUpdate0(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*UpdateClientResult, error) {
	if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
		return nil, err
	}

	headerStream, err := pr.originProver.SetupHeadersForUpdate(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup headers for update: header=%v %w", latestFinalizedHeader, err)
	}
	var results []*UpdateClientResult
	i := 0
	for h := range headerStream {
		if h.Error != nil {
			return nil, fmt.Errorf("failed to setup a header for update: i=%v %w", i, h.Error)
		}
		anyHeader, err := clienttypes.PackClientMessage(h.Header)
		if err != nil {
			return nil, fmt.Errorf("failed to pack header: i=%v header=%v %w", i, h.Header, err)
		}
		res, err := updateClient(ctx, pr.config.GetMaxChunkSizeForUpdateClient(), pr.lcpServiceClient, anyHeader, pr.config.ElcClientId, false, pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to update ELC: i=%v elc_client_id=%v %w", i, pr.config.ElcClientId, err)
		}
		// ensure the message is valid
		if _, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message); err != nil {
			return nil, fmt.Errorf("failed to decode headered proxy message: i=%v message=%x %w", i, res.Message, err)
		}
		results = append(results, &UpdateClientResult{
			Message:   res.Message,
			Signature: res.Signature,
		})
		i++
	}

	return results, nil
}
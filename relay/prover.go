package relay

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/datachainlab/lcp-go/sgx/ias"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Prover struct {
	config       ProverConfig
	originChain  core.Chain
	originProver core.Prover

	homePath string
	codec    codec.ProtoCodecMarshaler
	path     *core.PathEnd

	lcpServiceClient LCPServiceClient

	// state
	// registered key info for requesting lcp to generate proof.
	activeEnclaveKey *enclave.EnclaveKeyInfo
	// if not nil, the key is finalized.
	// if nil, the key is not finalized yet.
	unfinalizedMsgID core.MsgID
}

var (
	_ core.Prover = (*Prover)(nil)
)

func NewProver(config ProverConfig, originChain core.Chain, originProver core.Prover) (*Prover, error) {
	conn, err := grpc.Dial(
		config.LcpServiceAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(config.GetDialTimeout()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LCP service: %w", err)
	}
	return &Prover{config: config, originChain: originChain, originProver: originProver, lcpServiceClient: NewLCPServiceClient(conn)}, nil
}

func (pr *Prover) GetOriginProver() core.Prover {
	return pr.originProver
}

// Init initializes the chain
func (pr *Prover) Init(homePath string, timeout time.Duration, codec codec.ProtoCodecMarshaler, debug bool) error {
	pr.homePath = homePath
	pr.codec = codec
	if pr.config.IsDebugEnclave {
		ias.SetAllowDebugEnclaves()
	}
	if err := pr.originChain.Init(homePath, timeout, codec, debug); err != nil {
		return err
	}
	if err := pr.originProver.Init(homePath, timeout, codec, debug); err != nil {
		return err
	}
	if err := os.MkdirAll(pr.dbPath(), os.ModePerm); err != nil {
		return err
	}
	return nil
}

// SetRelayInfo sets source's path and counterparty's info to the chain
func (pr *Prover) SetRelayInfo(path *core.PathEnd, counterparty *core.ProvableChain, counterpartyPath *core.PathEnd) error {
	pr.path = path
	return nil
}

// SetupForRelay performs chain-specific setup before starting the relay
func (pr *Prover) SetupForRelay(ctx context.Context) error {
	return nil
}

// GetChainID returns the chain ID
func (pr *Prover) GetChainID() string {
	return pr.originChain.ChainID()
}

// CreateInitialLightClientState returns a pair of ClientState and ConsensusState based on the state of the self chain at `height`.
// These states will be submitted to the counterparty chain as MsgCreateClient.
// If `height` is nil, the latest finalized height is selected automatically.
func (pr *Prover) CreateInitialLightClientState(height exported.Height) (exported.ClientState, exported.ConsensusState, error) {
	if res, err := pr.createELC(pr.config.ElcClientId, height); err != nil {
		return nil, nil, err
	} else if res == nil {
		log.GetLogger().Info("no need to create ELC", "client_id", pr.config.ElcClientId)
	}

	clientState := &lcptypes.ClientState{
		LatestHeight:         clienttypes.Height{},
		Mrenclave:            pr.config.GetMrenclave(),
		KeyExpiration:        pr.config.KeyExpiration,
		AllowedQuoteStatuses: pr.config.AllowedQuoteStatuses,
		AllowedAdvisoryIds:   pr.config.AllowedAdvisoryIds,
	}
	consensusState := &lcptypes.ConsensusState{}
	// NOTE after creates client, register an enclave key into the client state
	return clientState, consensusState, nil
}

// GetLatestFinalizedHeader returns the latest finalized header on this chain
// The returned header is expected to be the latest one of headers that can be verified by the light client
func (pr *Prover) GetLatestFinalizedHeader() (core.Header, error) {
	return pr.originProver.GetLatestFinalizedHeader()
}

// SetupHeadersForUpdate returns the finalized header and any intermediate headers needed to apply it to the client on the counterpaty chain
// The order of the returned header slice should be as: [<intermediate headers>..., <update header>]
// if the header slice's length == nil and err == nil, the relayer should skips the update-client
func (pr *Prover) SetupHeadersForUpdate(dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]core.Header, error) {
	if err := pr.UpdateEKIfNeeded(context.TODO(), dstChain); err != nil {
		return nil, err
	}

	headers, err := pr.originProver.SetupHeadersForUpdate(dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, nil
	}
	var (
		messages   [][]byte
		signatures [][]byte
	)
	for _, h := range headers {
		anyHeader, err := clienttypes.PackClientMessage(h)
		if err != nil {
			return nil, err
		}
		res, err := pr.lcpServiceClient.UpdateClient(context.TODO(), &elc.MsgUpdateClient{
			ClientId:     pr.config.ElcClientId,
			Header:       anyHeader,
			IncludeState: false,
			Signer:       pr.activeEnclaveKey.EnclaveKeyAddress,
		})
		if err != nil {
			return nil, err
		}
		// ensure the message is valid
		if _, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message); err != nil {
			return nil, err
		}
		messages = append(messages, res.Message)
		signatures = append(signatures, res.Signature)
	}

	var updates []core.Header
	// NOTE: assume that the messages length and the signatures length are the same
	if pr.config.MessageAggregation {
		log.GetLogger().Info("aggregateMessages", "num_messages", len(messages))
		update, err := pr.aggregateMessages(messages, signatures, pr.activeEnclaveKey.EnclaveKeyAddress)
		if err != nil {
			return nil, err
		}
		updates = append(updates, update)
	} else {
		log.GetLogger().Info("updateClient", "num_messages", len(messages))
		for i := 0; i < len(messages); i++ {
			updates = append(updates, &lcptypes.UpdateClientMessage{
				ProxyMessage: messages[i],
				Signer:       pr.activeEnclaveKey.EnclaveKeyAddress,
				Signature:    signatures[i],
			})
		}
	}
	return updates, nil
}

func (pr *Prover) aggregateMessages(messages [][]byte, signatures [][]byte, signer []byte) (*lcptypes.UpdateClientMessage, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("aggregateMessages: messages must not be empty")
	} else if len(messages) != len(signatures) {
		return nil, fmt.Errorf("aggregateMessages: messages and signatures must have the same length: messages=%v signatures=%v", len(messages), len(signatures))
	}
	for {
		batches, err := splitIntoMultiBatch(messages, signatures, signer, pr.config.GetMessageAggregationBatchSize())
		if err != nil {
			return nil, err
		}
		if n := len(batches); n == 1 {
			if mn := len(batches[0].Messages); mn == 0 {
				return nil, fmt.Errorf("unexpected error: messages must not be empty")
			} else if mn == 1 {
				return &lcptypes.UpdateClientMessage{
					ProxyMessage: batches[0].Messages[0],
					Signer:       batches[0].Signer,
					Signature:    batches[0].Signatures[0],
				}, nil
			} else {
				resp, err := pr.lcpServiceClient.AggregateMessages(context.TODO(), &elc.MsgAggregateMessages{
					Signer:     batches[0].Signer,
					Messages:   batches[0].Messages,
					Signatures: batches[0].Signatures,
				})
				if err != nil {
					return nil, err
				}
				return &lcptypes.UpdateClientMessage{
					ProxyMessage: resp.Message,
					Signer:       resp.Signer,
					Signature:    resp.Signature,
				}, nil
			}
		} else if n == 0 {
			return nil, fmt.Errorf("unexpected error: batches must not be empty")
		} else {
			log.GetLogger().Info("aggregateMessages", "num_batches", n)
		}
		messages = nil
		signatures = nil
		for _, b := range batches {
			resp, err := pr.lcpServiceClient.AggregateMessages(context.TODO(), &elc.MsgAggregateMessages{
				Signer:     b.Signer,
				Messages:   b.Messages,
				Signatures: b.Signatures,
			})
			if err != nil {
				return nil, err
			}
			messages = append(messages, resp.Message)
			signatures = append(signatures, resp.Signature)
		}
	}
}

func splitIntoMultiBatch(messages [][]byte, signatures [][]byte, signer []byte, messageBatchSize uint64) ([]*elc.MsgAggregateMessages, error) {
	var res []*elc.MsgAggregateMessages
	var currentMessages [][]byte
	var currentBatchStartIndex uint64 = 0
	if messageBatchSize < 2 {
		return nil, fmt.Errorf("messageBatchSize must be greater than 1")
	}
	for i := 0; i < len(messages); i++ {
		currentMessages = append(currentMessages, messages[i])
		if uint64(len(currentMessages)) == messageBatchSize {
			res = append(res, &elc.MsgAggregateMessages{
				Signer:     signer,
				Messages:   currentMessages,
				Signatures: signatures[currentBatchStartIndex : currentBatchStartIndex+messageBatchSize],
			})
			currentMessages = nil
			currentBatchStartIndex = uint64(i + 1)
		}
	}
	if len(currentMessages) > 0 {
		res = append(res, &elc.MsgAggregateMessages{
			Signer:     signer,
			Messages:   currentMessages,
			Signatures: signatures[currentBatchStartIndex:],
		})
	}
	return res, nil
}

func (pr *Prover) CheckRefreshRequired(counterparty core.ChainInfoICS02Querier) (bool, error) {
	return pr.originProver.CheckRefreshRequired(counterparty)
}

func (pr *Prover) ProveState(ctx core.QueryContext, path string, value []byte) ([]byte, clienttypes.Height, error) {
	proof, proofHeight, err := pr.originProver.ProveState(ctx, path, value)
	if err != nil {
		return nil, clienttypes.Height{}, err
	}
	res, err := pr.lcpServiceClient.VerifyMembership(ctx.Context(), &elc.MsgVerifyMembership{
		ClientId:    pr.config.ElcClientId,
		Prefix:      []byte(exported.StoreKey),
		Path:        path,
		Value:       value,
		ProofHeight: proofHeight,
		Proof:       proof,
		Signer:      pr.activeEnclaveKey.EnclaveKeyAddress,
	})
	if err != nil {
		return nil, clienttypes.Height{}, err
	}
	message, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message)
	if err != nil {
		return nil, clienttypes.Height{}, err
	}
	sc, err := message.GetVerifyMembershipProxyMessage()
	if err != nil {
		return nil, clienttypes.Height{}, err
	}
	cp, err := lcptypes.EthABIEncodeCommitmentProof(&lcptypes.CommitmentProof{
		Message:   res.Message,
		Signer:    common.BytesToAddress(res.Signer),
		Signature: res.Signature,
	})
	if err != nil {
		return nil, clienttypes.Height{}, err
	}
	return cp, sc.Height, nil
}

// ProveHostConsensusState returns an existence proof of the consensus state at `height`
// This proof would be ignored in ibc-go, but it is required to `getSelfConsensusState` of ibc-solidity.
func (pr *Prover) ProveHostConsensusState(ctx core.QueryContext, height exported.Height, consensusState exported.ConsensusState) (proof []byte, err error) {
	return pr.originProver.ProveHostConsensusState(ctx, height, consensusState)
}

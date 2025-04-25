package relay

import (
	"bytes"
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
	"github.com/datachainlab/lcp-go/sgx"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	"github.com/hyperledger-labs/yui-relayer/signer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Prover struct {
	config       ProverConfig
	originChain  core.Chain
	originProver core.Prover

	homePath         string
	codec            codec.ProtoCodecMarshaler
	path             *core.PathEnd
	counterpartyPath *core.PathEnd

	lcpServiceClient LCPServiceClient

	eip712Signer *EIP712Signer

	// state
	// registered key info for requesting lcp to generate proof.
	activeEnclaveKey *enclave.EnclaveKeyInfo
	// if nil, the key is finalized.
	// if not nil, the key is not finalized yet.
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
	var eip712Signer *EIP712Signer
	if config.OperatorSigner != nil {
		signer, err := config.OperatorSigner.GetCachedValue().(signer.SignerConfig).Build()
		if err != nil {
			return nil, err
		}
		eip712Signer = NewEIP712Signer(signer)
	}
	return &Prover{config: config, originChain: originChain, originProver: originProver, lcpServiceClient: NewLCPServiceClient(conn), eip712Signer: eip712Signer}, nil
}

func (pr *Prover) GetOriginProver() core.Prover {
	return pr.originProver
}

// Init initializes the chain
func (pr *Prover) Init(homePath string, timeout time.Duration, codec codec.ProtoCodecMarshaler, debug bool) error {
	pr.homePath = homePath
	pr.codec = codec
	res, err := pr.lcpServiceClient.EnclaveInfo(context.Background(), &enclave.QueryEnclaveInfoRequest{})
	if err != nil {
		return fmt.Errorf("failed to get enclave info: %w", err)
	}
	if !bytes.Equal(res.Mrenclave, pr.config.GetMrenclave()) {
		return fmt.Errorf("mismatched mrenclave between the prover and the LCP service: prover=%x lcp=%x", pr.config.GetMrenclave(), res.Mrenclave)
	}
	if res.EnclaveDebug != pr.config.IsDebugEnclave {
		return fmt.Errorf("mismatched debug enclave between the prover and the LCP service: prover=%v lcp=%v", pr.config.IsDebugEnclave, res.EnclaveDebug)
	}
	if pr.config.IsDebugEnclave {
		sgx.SetAllowDebugEnclaves()
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
	pr.counterpartyPath = counterpartyPath
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
func (pr *Prover) CreateInitialLightClientState(ctx context.Context, height exported.Height) (exported.ClientState, exported.ConsensusState, error) {
	ops, err := pr.GetOperators()
	if err != nil {
		return nil, nil, err
	}
	var operators [][]byte
	for _, op := range ops {
		operators = append(operators, op.Bytes())
	}
	zkDCAPVerifierInfos, err := pr.getZKDCAPVerifierInfos()
	if err != nil {
		return nil, nil, err
	}
	clientState := &lcptypes.ClientState{
		LatestHeight:                             clienttypes.Height{},
		Mrenclave:                                pr.config.GetMrenclave(),
		KeyExpiration:                            pr.config.KeyExpiration,
		AllowedQuoteStatuses:                     pr.config.AllowedQuoteStatuses,
		AllowedAdvisoryIds:                       pr.config.AllowedAdvisoryIds,
		Operators:                                operators,
		OperatorsNonce:                           0,
		OperatorsThresholdNumerator:              pr.GetOperatorsThreshold().Numerator,
		OperatorsThresholdDenominator:            pr.GetOperatorsThreshold().Denominator,
		CurrentTcbEvaluationDataNumber:           pr.config.CurrentTcbEvaluationDataNumber,
		TcbEvaluationDataNumberUpdateGracePeriod: pr.config.TcbEvaluationDataNumberUpdateGracePeriod,
		ZkdcapVerifierInfos:                      zkDCAPVerifierInfos,
	}

	consensusState := &lcptypes.ConsensusState{}

	if res, err := pr.createELC(ctx, pr.config.ElcClientId, height); err != nil {
		return nil, nil, fmt.Errorf("failed to create ELC: %w", err)
	} else if res == nil {
		pr.getLogger().Info("no need to create ELC", "elc_client_id", pr.config.ElcClientId)
	}

	// NOTE after creates client, register an enclave key into the client state
	return clientState, consensusState, nil
}

// GetLatestFinalizedHeader returns the latest finalized header on this chain
// The returned header is expected to be the latest one of headers that can be verified by the light client
func (pr *Prover) GetLatestFinalizedHeader(ctx context.Context) (core.Header, error) {
	return pr.originProver.GetLatestFinalizedHeader(ctx)
}

// SetupHeadersForUpdate returns the finalized header and any intermediate headers needed to apply it to the client on the counterparty chain
// The order of the returned header slice should be as: [<intermediate headers>..., <update header>]
// if the header slice's length == nil and err == nil, the relayer should skip the update-client
func (pr *Prover) SetupHeadersForUpdate(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]core.Header, error) {
	if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
		return nil, err
	}

	headers, err := pr.originProver.SetupHeadersForUpdate(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup headers for update: header=%v %w", latestFinalizedHeader, err)
	}
	if len(headers) == 0 {
		return nil, nil
	}
	var (
		messages   [][]byte
		signatures [][]byte
	)
	for i, h := range headers {
		anyHeader, err := clienttypes.PackClientMessage(h)
		if err != nil {
			return nil, fmt.Errorf("failed to pack header: i=%v header=%v %w", i, h, err)
		}
		res, err := updateClient(ctx, pr.config.GetMaxChunkSizeForUpdateClient(), pr.lcpServiceClient, anyHeader, pr.config.ElcClientId, false, pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to update ELC: i=%v elc_client_id=%v %w", i, pr.config.ElcClientId, err)
		}
		// ensure the message is valid
		if _, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message); err != nil {
			return nil, fmt.Errorf("failed to decode headered proxy message: i=%v message=%x %w", i, res.Message, err)
		}
		messages = append(messages, res.Message)
		signatures = append(signatures, res.Signature)
	}

	var updates []core.Header
	// NOTE: assume that the messages length and the signatures length are the same
	if pr.config.MessageAggregation {
		pr.getLogger().Info("aggregate messages", "num_messages", len(messages))
		update, err := aggregateMessages(ctx, pr.getLogger(), pr.config.GetMessageAggregationBatchSize(), pr.lcpServiceClient.AggregateMessages, messages, signatures, pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes())
		if err != nil {
			return nil, err
		}
		updates = append(updates, update)
	} else {
		pr.getLogger().Info("updateClient", "num_messages", len(messages))
		for i := 0; i < len(messages); i++ {
			updates = append(updates, &lcptypes.UpdateClientMessage{
				ProxyMessage: messages[i],
				Signatures:   [][]byte{signatures[i]},
			})
		}
	}
	return updates, nil
}

type MessageAggregator func(ctx context.Context, in *elc.MsgAggregateMessages, opts ...grpc.CallOption) (*elc.MsgAggregateMessagesResponse, error)

func aggregateMessages(
	ctx context.Context,
	logger *log.RelayLogger,
	batchSize uint64,
	messageAggregator MessageAggregator,
	messages [][]byte,
	signatures [][]byte,
	signer []byte,
) (*lcptypes.UpdateClientMessage, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("aggregateMessages: messages must not be empty")
	} else if len(messages) != len(signatures) {
		return nil, fmt.Errorf("aggregateMessages: messages and signatures must have the same length: messages=%v signatures=%v", len(messages), len(signatures))
	}
	for {
		batches, err := splitIntoMultiBatch(messages, signatures, signer, batchSize)
		if err != nil {
			return nil, err
		}
		if n := len(batches); n == 1 {
			if mn := len(batches[0].Messages); mn == 0 {
				return nil, fmt.Errorf("unexpected error: messages must not be empty")
			} else if mn == 1 {
				return &lcptypes.UpdateClientMessage{
					ProxyMessage: batches[0].Messages[0],
					Signatures:   [][]byte{batches[0].Signatures[0]},
				}, nil
			} else {
				m := elc.MsgAggregateMessages{
					Signer:     batches[0].Signer,
					Messages:   batches[0].Messages,
					Signatures: batches[0].Signatures,
				}
				resp, err := messageAggregator(ctx, &m)
				if err != nil {
					return nil, fmt.Errorf("failed to aggregate messages: msg=%v %w", m, err)
				}
				return &lcptypes.UpdateClientMessage{
					ProxyMessage: resp.Message,
					Signatures:   [][]byte{resp.Signature},
				}, nil
			}
		} else if n == 0 {
			return nil, fmt.Errorf("unexpected error: batches must not be empty")
		} else {
			logger.Info("aggregateMessages", "num_batches", n)
		}
		messages = nil
		signatures = nil
		for i, b := range batches {
			logger.Info("aggregateMessages", "batch_index", i, "num_messages", len(b.Messages))
			if len(b.Messages) == 1 {
				messages = append(messages, b.Messages[0])
				signatures = append(signatures, b.Signatures[0])
			} else {
				m := elc.MsgAggregateMessages{
					Signer:     b.Signer,
					Messages:   b.Messages,
					Signatures: b.Signatures,
				}
				resp, err := messageAggregator(ctx, &m)
				if err != nil {
					return nil, fmt.Errorf("failed to aggregate messages: batch_index=%v msg=%v %w", i, m, err)
				}
				messages = append(messages, resp.Message)
				signatures = append(signatures, resp.Signature)
			}
		}
	}
}

func splitIntoMultiBatch(messages [][]byte, signatures [][]byte, signer []byte, messageBatchSize uint64) ([]*elc.MsgAggregateMessages, error) {
	var res []*elc.MsgAggregateMessages
	var currentMessages [][]byte
	var currentBatchStartIndex uint64 = 0
	if messageBatchSize < 2 {
		return nil, fmt.Errorf("messageBatchSize must be greater than 1: messageBatchSize=%v", messageBatchSize)
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

func (pr *Prover) CheckRefreshRequired(ctx context.Context, counterparty core.ChainInfoICS02Querier) (bool, error) {
	return pr.originProver.CheckRefreshRequired(ctx, counterparty)
}

func (pr *Prover) ProveState(ctx core.QueryContext, path string, value []byte) ([]byte, clienttypes.Height, error) {
	proof, proofHeight, err := pr.originProver.ProveState(ctx, path, value)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed originProver.ProveState: path=%v value=%x %w", path, value, err)
	}
	m := elc.MsgVerifyMembership{
		ClientId:    pr.config.ElcClientId,
		Prefix:      []byte(exported.StoreKey),
		Path:        path,
		Value:       value,
		ProofHeight: proofHeight,
		Proof:       proof,
		Signer:      pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes(),
	}
	res, err := pr.lcpServiceClient.VerifyMembership(ctx.Context(), &m)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed ELC's VerifyMembership: elc_client_id=%v msg=%v %w", pr.config.ElcClientId, m, err)
	}
	message, err := lcptypes.EthABIDecodeHeaderedProxyMessage(res.Message)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed to decode headered proxy message: message=%x %w", res.Message, err)
	}
	sc, err := message.GetVerifyMembershipProxyMessage()
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed GetVerifyMembershipProxyMessage: message=%x %w", res.Message, err)
	}
	cp, err := lcptypes.EthABIEncodeCommitmentProofs(&lcptypes.CommitmentProofs{
		Message:    res.Message,
		Signatures: [][]byte{res.Signature},
	})
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed to encode commitment proof: %w", err)
	}
	return cp, sc.Height, nil
}

// ProveHostConsensusState returns an existence proof of the consensus state at `height`
// This proof would be ignored in ibc-go, but it is required to `getSelfConsensusState` of ibc-solidity.
func (pr *Prover) ProveHostConsensusState(ctx core.QueryContext, height exported.Height, consensusState exported.ConsensusState) (proof []byte, err error) {
	return pr.originProver.ProveHostConsensusState(ctx, height, consensusState)
}

func (pr *Prover) getLogger() *log.RelayLogger {
	logger := log.GetLogger().WithModule(ModuleName)
	if pr.path == nil {
		return logger
	}
	return logger.WithChain(pr.path.ChainID)
}

func (pr *Prover) getClientLogger(clientID string) *log.RelayLogger {
	logger := pr.getLogger()
	return &log.RelayLogger{
		Logger: logger.With(
			"client_id", clientID,
		),
	}
}

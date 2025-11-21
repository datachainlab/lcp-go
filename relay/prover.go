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
	"github.com/datachainlab/lcp-go/relay/shfu_grpc"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/datachainlab/lcp-go/sgx"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	"github.com/hyperledger-labs/yui-relayer/signer"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
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

// reconstructedHeader implements core.Header by wrapping a ClientMessage and Height
type reconstructedHeader struct {
	clientMessage exported.ClientMessage
	height        exported.Height
}

func (h *reconstructedHeader) GetHeight() exported.Height {
	return h.height
}

func (h *reconstructedHeader) ClientType() string {
	return h.clientMessage.ClientType()
}

func (h *reconstructedHeader) ValidateBasic() error {
	return h.clientMessage.ValidateBasic()
}

// ProtoMessage implements proto.Message interface
func (h *reconstructedHeader) ProtoMessage() {}

// Reset implements proto.Message interface
func (h *reconstructedHeader) Reset() {}

// String implements proto.Message interface
func (h *reconstructedHeader) String() string {
	return h.clientMessage.String()
}

// shouldUseSHFUGRPC determines whether to use SHFU gRPC server based on config and environment variable
// Environment variable SHFU_GRPC_ENABLE=yes enables gRPC, address comes from config
func (pr *Prover) shouldUseSHFUGRPC() (bool, string) {
	// Check if gRPC is enabled via environment variable
	envEnable := os.Getenv("SHFU_GRPC_ENABLE")
	if envEnable != "yes" {
		// If environment variable is not "yes", don't use gRPC regardless of config
		return false, ""
	}

	// Environment variable enables gRPC, check if address is configured
	if pr.config.ShfuGrpcAddress != "" {
		return true, pr.config.ShfuGrpcAddress
	}

	// gRPC enabled but no address configured
	return false, ""
}

// getUpdateClientFromGRPC retrieves SHFU results from gRPC server using height range
func getUpdateClientFromGRPC(ctx context.Context, logger *log.RelayLogger, grpcAddress string, targetChain core.Chain, counterparty core.Chain, latestFinalizedHeader core.Header) ([]*shfu_storage.UpdateClientResult, error) {
	logger.InfoContext(ctx, "using SHFU gRPC server", "address", grpcAddress)

	// Get chain ID from target chain and counterparty chain
	chainID := targetChain.ChainID()
	counterpartyChainID := counterparty.ChainID()

	// Use a default toHeight (for now, use fromHeight + 1 as a simple default)
	toHeight := clienttypes.Height{
		RevisionNumber: latestFinalizedHeader.GetHeight().GetRevisionNumber(),
		RevisionHeight: latestFinalizedHeader.GetHeight().GetRevisionHeight(),
	}

	// Get SHFU record by height range
	record, err := shfu_grpc.GetSHFUByHeight(ctx, grpcAddress, chainID, counterpartyChainID, toHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHFU by height: %w", err)
	}

	if record == nil {
		logger.InfoContext(ctx, "no SHFU record found from gRPC server",
			"chain_id", chainID,
			"to_height", fmt.Sprintf("%d-%d", toHeight.RevisionNumber, toHeight.RevisionHeight))
		return []*shfu_storage.UpdateClientResult{}, nil
	}

	logger.InfoContext(ctx, "retrieved SHFU record from gRPC server",
		"chain_id", chainID,
		"to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight),
		"num_results", len(record.UpdateClientResults))

	return record.UpdateClientResults, nil
}

func NewProver(config ProverConfig, originChain core.Chain, originProver core.Prover) (*Prover, error) {
	conn, err := grpc.Dial(
		config.LcpServiceAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(config.GetDialTimeout()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
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
		pr.getLogger().InfoContext(ctx, "no need to create ELC", "elc_client_id", pr.config.ElcClientId)
	}

	// NOTE after creates client, register an enclave key into the client state
	return clientState, consensusState, nil
}

// GetLatestFinalizedHeader returns the latest finalized header on this chain
// The returned header is expected to be the latest one of headers that can be verified by the light client
func (pr *Prover) GetLatestFinalizedHeader(ctx context.Context) (core.Header, error) {
	// Use SHFU gRPC server if configured (environment variable or config), otherwise use origin prover
	useGRPC, grpcAddress := pr.shouldUseSHFUGRPC()
	if useGRPC {
		pr.getLogger().InfoContext(ctx, "using SHFU gRPC server for latest finalized header", "address", grpcAddress)

		// Get chain ID from origin chain
		chainID := pr.originChain.ChainID()
		// Note: This is called from GetLatestFinalizedHeader, so we don't have dstChain info
		// For now, we'll pass empty string as counterparty chain ID - this needs architectural change
		header, err := shfu_grpc.GetLatestFinalizedHeader(ctx, grpcAddress, chainID, "", pr.codec)
		if err != nil {
			return nil, err
		}

		pr.getLogger().InfoContext(ctx, "retrieved finalized header from gRPC server",
			"chain_id", chainID,
			"height", header.GetHeight().String())

		return header, nil
	} else {
		pr.getLogger().InfoContext(ctx, "using origin prover for latest finalized header")
		return pr.originProver.GetLatestFinalizedHeader(ctx)
	}
}

// setupHeadersForUpdate0 performs the initial setup and updateClient calls
// Returns the processed updateClient results for aggregation
func (pr *Prover) setupHeadersForUpdate0(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*shfu_storage.UpdateClientResult, error) {
	if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
		return nil, err
	}
	/*
		if pr.activeEnclaveKey == nil {
			_, err := pr.loadEKIAndCheckUpdateNeeded(ctx, dstChain)
			if err != nil {
				return nil, err
			}
			if pr.activeEnclaveKey == nil {
				return nil, fmt.Errorf("activeEnclaveKey is nil after loadEKIAndCheckUpdateNeeded")
			}
		}
	*/
	headerStream, err := pr.originProver.SetupHeadersForUpdate(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup headers for update: header=%v %w", latestFinalizedHeader, err)
	}
	var results []*shfu_storage.UpdateClientResult
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
		results = append(results, &shfu_storage.UpdateClientResult{
			Message:   res.Message,
			Signature: res.Signature,
		})
		i++
	}

	return results, nil
}

// SetupHeadersForUpdate returns the finalized header and any intermediate headers needed to apply it to the client on the counterparty chain
// The order of the returned header slice should be as: [<intermediate headers>..., <update header>]
// if the header slice's length == nil and err == nil, the relayer should skip the update-client
func (pr *Prover) SetupHeadersForUpdate(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) (<-chan *core.HeaderOrError, error) {
	var results []*shfu_storage.UpdateClientResult
	var err error
	/*
		if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
			return nil, err
		}
	*/
	// Use SHFU gRPC server if configured (environment variable or config), otherwise use local implementation
	useGRPC, grpcAddress := pr.shouldUseSHFUGRPC()
	if useGRPC {
		if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
			return nil, err
		}
		results, err = getUpdateClientFromGRPC(ctx, pr.getLogger(), grpcAddress, pr.originChain, dstChain, latestFinalizedHeader)
	} else {
		pr.getLogger().InfoContext(ctx, "using local SHFU implementation")
		results, err = pr.setupHeadersForUpdate0(ctx, dstChain, latestFinalizedHeader)
	}

	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return core.MakeHeaderStream(), nil
	}

	// Extract messages and signatures from results for existing aggregation logic
	var messages [][]byte
	var signatures [][]byte
	for _, result := range results {
		messages = append(messages, result.Message)
		signatures = append(signatures, result.Signature)
	}

	var updates []core.Header
	// NOTE: assume that the messages length and the signatures length are the same
	if pr.config.MessageAggregation {
		pr.getLogger().InfoContext(ctx, "aggregate messages", "num_messages", len(messages))
		update, err := aggregateMessages(ctx, pr.getLogger(), pr.config.GetMessageAggregationBatchSize(), pr.lcpServiceClient.AggregateMessages, messages, signatures, pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes())
		if err != nil {
			return nil, err
		}
		updates = append(updates, update)
	} else {
		pr.getLogger().InfoContext(ctx, "updateClient", "num_messages", len(messages))
		for i := 0; i < len(messages); i++ {
			updates = append(updates, &lcptypes.UpdateClientMessage{
				ProxyMessage: messages[i],
				Signatures:   [][]byte{signatures[i]},
			})
		}
	}
	return core.MakeHeaderStream(updates...), nil
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
			logger.InfoContext(ctx, "aggregateMessages", "num_batches", n)
		}
		messages = nil
		signatures = nil
		for i, b := range batches {
			logger.InfoContext(ctx, "aggregateMessages", "batch_index", i, "num_messages", len(b.Messages))
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

func (pr *Prover) getClientLogger() *log.RelayLogger {
	clientID := ""
	if pr.originChain.Path() != nil {
		clientID = pr.originChain.Path().ClientID
	}
	logger := pr.getLogger()
	return &log.RelayLogger{
		Logger: logger.With(
			"client_id", clientID,
		),
	}
}

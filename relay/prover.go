package relay

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/cosmos/cosmos-sdk/codec"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	tmclient "github.com/cosmos/ibc-go/v8/modules/light-clients/07-tendermint"
	lcptypes "github.com/datachainlab/lcp-go/light-clients/lcp/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	elcupdater_grpc "github.com/datachainlab/lcp-go/relay/elcupdater/grpc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/datachainlab/lcp-go/sgx"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	yuiotelcore "github.com/hyperledger-labs/yui-relayer/otelcore"
	"github.com/hyperledger-labs/yui-relayer/signer"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Prover struct {
	config                ProverConfig
	originChain           core.Chain
	originProver          core.Prover
	sourceHeaderCollector ExplicitStateSourceHeaderCollector

	homePath         string
	codec            codec.ProtoCodecMarshaler
	path             *core.PathEnd
	counterpartyPath *core.PathEnd

	lcpServiceClient     LCPServiceClient
	explicitStateQueryMu sync.Mutex

	eip712Signer *EIP712Signer

	// state
	// registered key info for requesting lcp to generate proof.
	activeEnclaveKey *enclave.EnclaveKeyInfo
	// if nil, the key is finalized.
	// if not nil, the key is not finalized yet.
	unfinalizedMsgID core.MsgID

	gauge *Int64Gauge
}

type ExplicitStateSourceHeaderCollector func(context.Context, core.FinalityAwareChain, core.Header) ([]*ExplicitStateSourceHeaderUnit, error)

type ExplicitStateChunkProvider interface {
	SetupExplicitStateChunksForUpdate(context.Context, core.FinalityAwareChain, core.Header) ([]*ExplicitStateSourceHeaderUnit, error)
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
	return &Prover{config: config, originChain: originChain, originProver: originProver, lcpServiceClient: NewLCPServiceClient(conn), eip712Signer: eip712Signer, gauge: nil}, nil
}

func (pr *Prover) GetConfig() *ProverConfig {
	return &pr.config
}

func (pr *Prover) GetOriginProver() core.Prover {
	return pr.originProver
}

func (pr *Prover) GetOriginChain() core.Chain {
	return pr.originChain
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

	if gauge, err := NewInt64Gauge(
		"update_client_height",
		fmt.Sprintf("LCP update client height for chain %s against counterparty %s", pr.originChain.ChainID(), counterparty.ChainID()),
		metric.WithAttributes(
			attribute.String("chain_id", pr.originChain.ChainID()),
			attribute.String("counterparty_chain_id", counterparty.ChainID()),
		),
	); err != nil {
		return err
	} else {
		pr.gauge = gauge
	}

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
	// Use ELC updater gRPC server if configured (environment variable and config), otherwise use origin prover
	useGRPC, grpcAddress, err := pr.shouldUseELCUpdaterGRPC()
	if err != nil {
		return nil, err
	}
	if useGRPC {
		pr.getLogger().InfoContext(ctx, "using ELC updater gRPC server for latest finalized header", "address", grpcAddress)

		// Get chain ID from origin chain
		chainID := pr.originChain.ChainID()

		// Note: This is called from GetLatestFinalizedHeader, so we don't have dstChain info
		// For now, we'll pass empty string as counterparty chain ID - this needs architectural change
		header, err := elcupdater_grpc.GetLatestFinalizedHeader(ctx, grpcAddress, chainID, "", pr.codec)
		if err != nil {
			return nil, err
		}

		// Check if header is nil
		if header == nil {
			err := fmt.Errorf("received nil header from ELC updater gRPC server for chain %s", chainID)
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

// SetupHeadersForUpdate returns the finalized header and any intermediate headers needed to apply it to the client on the counterparty chain
// The order of the returned header slice should be as: [<intermediate headers>..., <update header>]
// if the header slice's length == nil and err == nil, the relayer should skip the update-client
func (pr *Prover) SetupHeadersForUpdate(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) (<-chan *core.HeaderOrError, error) {
	results, err := pr.updateClient(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return core.MakeHeaderStream(), nil
	}

	// Extract messages and signatures from results for existing aggregation logic
	var messages [][]byte
	var signatures [][]byte
	var signers [][]byte
	for _, result := range results {
		messages = append(messages, result.Message)
		signatures = append(signatures, result.Signature)
		signers = append(signers, result.Signer)
	}

	var updates []core.Header
	// NOTE: assume that the messages length and the signatures length are the same
	if pr.config.MessageAggregation {
		pr.getLogger().InfoContext(ctx, "aggregate messages", "num_messages", len(messages))

		signerMessages, err := splitMessagesBySigner(messages, signatures, signers)
		if err != nil {
			return nil, err
		}
		for _, m := range signerMessages {
			update, err := aggregateMessages(ctx, pr.getLogger(), pr.config.GetMessageAggregationBatchSize(), pr.lcpServiceClient.AggregateMessages, m.Messages, m.Signatures, m.Signer)
			if err != nil {
				return nil, err
			}
			updates = append(updates, update)
		}
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

// updateELCForUpdateClient performs the initial setup and updateClient calls
// Returns the processed updateClient results for aggregation
func (pr *Prover) updateELCForUpdateClient(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*elcupdater_storage.UpdateClientResult, error) {
	sourceHeaderUnits, err := pr.collectExplicitStateSourceHeaderUnitsForUpdate(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, err
	}
	anyHeaders := extractAnyHeadersFromSourceUnits(sourceHeaderUnits)

	if len(anyHeaders) == 0 {
		if pr.gauge != nil {
			pr.gauge.Set(ctx, int64(latestFinalizedHeader.GetHeight().GetRevisionHeight()))
		}
		return nil, nil
	}

	signer := pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes()
	plan, err := pr.buildExplicitStateUpdatePlanForHeaderUnits(
		ctx,
		extractExplicitStateHeaderUnits(sourceHeaderUnits),
		pr.config.ElcClientId,
		false,
		signer,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to plan explicit-state update batch: elc_client_id=%v %w", pr.config.ElcClientId, err)
	}
	pr.getLogger().InfoContext(
		ctx,
		"explicit-state update plan",
		"strategy", explicitStateLaneStrategy(),
		"num_source_headers", len(sourceHeaderUnits),
		"num_units", len(plan.Units),
		"num_lanes", len(plan.LaneWidths),
		"lane_widths", plan.LaneWidths,
		"lane_limit_reason", explicitStateLaneLimitReason(sourceHeaderUnits, plan.LaneWidths),
	)
	results, err := pr.executeExplicitStateUpdatePlan(ctx, plan)
	if err != nil {
		return nil, fmt.Errorf("failed to update ELC: elc_client_id=%v %w", pr.config.ElcClientId, err)
	}

	for _, result := range results {
		if _, err := lcptypes.EthABIDecodeHeaderedProxyMessage(result.Message); err != nil {
			return nil, fmt.Errorf("failed to decode headered proxy message: message=%x %w", result.Message, err)
		}
	}

	if pr.gauge != nil {
		pr.gauge.Set(ctx, int64(latestFinalizedHeader.GetHeight().GetRevisionHeight()))
	}
	return results, nil
}

func (pr *Prover) collectExplicitStateSourceHeaderUnitsForUpdate(
	ctx context.Context,
	dstChain core.FinalityAwareChain,
	latestFinalizedHeader core.Header,
) ([]*ExplicitStateSourceHeaderUnit, error) {
	if pr.sourceHeaderCollector != nil {
		return pr.sourceHeaderCollector(ctx, dstChain, latestFinalizedHeader)
	}
	if provider, ok := unwrapExplicitStateOriginProver(pr.originProver).(ExplicitStateChunkProvider); ok {
		units, err := provider.SetupExplicitStateChunksForUpdate(ctx, dstChain, latestFinalizedHeader)
		if err != nil {
			return nil, err
		}
		if len(units) > 0 {
			return units, nil
		}
	}
	if useExplicitStateTMMultiHeaderCollector() {
		unwrappedProver := unwrapExplicitStateOriginProver(pr.originProver)
		unwrappedChain := unwrapExplicitStateOriginChain(pr.originChain)
		headerProvider, okHeaderProvider := unwrappedProver.(interface {
			UpdateLightClient(context.Context, int64) (*tmclient.Header, error)
		})
		valsetQuerier, okValsetQuerier := unwrappedChain.(interface {
			QueryValsetAtHeight(context.Context, clienttypes.Height) (*tmproto.ValidatorSet, error)
		})
		pr.getLogger().InfoContext(
			ctx,
			"explicit-state tm multi-header collector check",
			"origin_prover_type", fmt.Sprintf("%T", pr.originProver),
			"origin_chain_type", fmt.Sprintf("%T", pr.originChain),
			"unwrapped_prover_type", fmt.Sprintf("%T", unwrappedProver),
			"unwrapped_chain_type", fmt.Sprintf("%T", unwrappedChain),
			"ok_header_provider", okHeaderProvider,
			"ok_valset_querier", okValsetQuerier,
			"codec_initialized", pr.codec != nil,
		)
		if okHeaderProvider && okValsetQuerier && pr.codec != nil {
			if units, ok, err := collectTendermintSharedTrustedSourceHeaderUnits(
				ctx,
				pr.codec,
				dstChain,
				headerProvider,
				valsetQuerier,
				latestFinalizedHeader,
				explicitStateTMMultiHeaderLimit(),
			); err != nil {
				return nil, err
			} else if ok {
				pr.getLogger().InfoContext(
					ctx,
					"explicit-state tm multi-header collector selected",
					"num_source_headers", len(units),
					"max_source_headers", explicitStateTMMultiHeaderLimit(),
				)
				return units, nil
			} else {
				pr.getLogger().InfoContext(
					ctx,
					"explicit-state tm multi-header collector fallback",
					"reason", "collector_returned_no_units",
				)
			}
		} else {
			pr.getLogger().InfoContext(
				ctx,
				"explicit-state tm multi-header collector fallback",
				"reason", "missing_runtime_support",
			)
		}
	}
	headerStream, err := pr.originProver.SetupHeadersForUpdate(ctx, dstChain, latestFinalizedHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup headers for update: header=%v %w", latestFinalizedHeader, err)
	}
	sourceHeaderUnits, err := collectExplicitStateSourceHeaderUnits(headerStream)
	if err != nil {
		return nil, err
	}
	return sourceHeaderUnits, nil
}

func unwrapExplicitStateOriginProver(prover core.Prover) core.Prover {
	for {
		switch p := prover.(type) {
		case *yuiotelcore.Prover:
			prover = p.Prover
		default:
			return prover
		}
	}
}

func unwrapExplicitStateOriginChain(chain core.Chain) core.Chain {
	for {
		switch c := chain.(type) {
		case *yuiotelcore.Chain:
			chain = c.Chain
		default:
			return chain
		}
	}
}

func splitMessagesBySigner(messages [][]byte, signatures [][]byte, signers [][]byte) ([]*elc.MsgAggregateMessages, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("messages must not be empty")
	}

	var res []*elc.MsgAggregateMessages
	i0 := 0 // batch start index
	for i := 0; i < len(messages); i++ {
		if (i == len(messages)-1) || !bytes.Equal(signers[i], signers[i+1]) {
			res = append(res, &elc.MsgAggregateMessages{
				Signer:     signers[i0],
				Messages:   messages[i0 : i+1],
				Signatures: signatures[i0 : i+1],
			})
			i0 = i + 1
		}
	}
	return res, nil
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

	signer, err := pr.getEnclaveKeyAddressBytes(ctx.Context(), pr.path.ChainID, pr.counterpartyPath.ChainID)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed to get enclave key address: %w", err)
	}
	var cp lcptypes.CommitmentProofs
	if len(value) == 0 {
		m := elc.MsgVerifyNonMembership{
			ClientId:    pr.config.ElcClientId,
			Prefix:      []byte(exported.StoreKey),
			Path:        path,
			ProofHeight: proofHeight,
			Proof:       proof,
			Signer:      signer,
		}
		res, err := pr.lcpServiceClient.VerifyNonMembership(ctx.Context(), &m)
		if err != nil {
			return nil, clienttypes.Height{}, fmt.Errorf("failed ELC's VerifyNonMembership: elc_client_id=%v msg=%v %w", pr.config.ElcClientId, m, err)
		}
		cp.Message = res.Message
		cp.Signatures = [][]byte{res.Signature}
	} else {
		m := elc.MsgVerifyMembership{
			ClientId:    pr.config.ElcClientId,
			Prefix:      []byte(exported.StoreKey),
			Path:        path,
			Value:       value,
			ProofHeight: proofHeight,
			Proof:       proof,
			Signer:      signer,
		}
		res, err := pr.lcpServiceClient.VerifyMembership(ctx.Context(), &m)
		if err != nil {
			return nil, clienttypes.Height{}, fmt.Errorf("failed ELC's VerifyMembership: elc_client_id=%v msg=%v %w", pr.config.ElcClientId, m, err)
		}
		cp.Message = res.Message
		cp.Signatures = [][]byte{res.Signature}
	}

	message, err := lcptypes.EthABIDecodeHeaderedProxyMessage(cp.Message)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed to decode headered proxy message: message=%x %w", cp.Message, err)
	}
	sc, err := message.GetVerifyMembershipProxyMessage()
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed GetVerifyMembershipProxyMessage: message=%x %w", cp.Message, err)
	}
	cpEnc, err := lcptypes.EthABIEncodeCommitmentProofs(&cp)
	if err != nil {
		return nil, clienttypes.Height{}, fmt.Errorf("failed to encode commitment proof: %w", err)
	}
	return cpEnc, sc.Height, nil
}

// ProveHostConsensusState returns an existence proof of the consensus state at `height`
// This proof would be ignored in ibc-go, but it is required to `getSelfConsensusState` of ibc-solidity.
func (pr *Prover) ProveHostConsensusState(ctx core.QueryContext, height exported.Height, consensusState exported.ConsensusState) (proof []byte, err error) {
	return pr.originProver.ProveHostConsensusState(ctx, height, consensusState)
}

func (pr *Prover) getLogger() *log.RelayLogger {
	logger := log.GetLogger().WithModule("lcp-prover")
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

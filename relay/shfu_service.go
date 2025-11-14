package relay

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/datachainlab/lcp-go/relay/shfu_grpc"
	"github.com/hyperledger-labs/yui-relayer/core"
	"google.golang.org/grpc"
)

// const DefaultPollInterval = 10 * time.Second
const DefaultPollInterval = 120 * time.Second

// SHFUChainPair represents a target chain and its counterparty chain pair
type SHFUChainPair struct {
	TargetChain       *core.ProvableChain
	CounterpartyChain *core.ProvableChain
}

type SHFUService struct {
	Storage      SHFUStorage
	ChainPairs   []*SHFUChainPair // Changed from TargetChains to ChainPairs
	PollInterval time.Duration
	GRPCAddr     string // gRPC server address (e.g., ":8080")
}

// NewSHFUService creates a new SHFUService
func NewSHFUService(storage SHFUStorage, chainPairs []*SHFUChainPair, grpcAddr string) *SHFUService {
	return &SHFUService{
		Storage:      storage,
		ChainPairs:   chainPairs,
		PollInterval: DefaultPollInterval,
		GRPCAddr:     grpcAddr,
	}
}

func (srv *SHFUService) SHFUServiceRun(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel for signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	// Calculate fail channel buffer size: signal handling + updaters + grpc server
	failBufferSize := 1 + len(srv.ChainPairs) + 1
	fails := make(chan error, failBufferSize)
	defer close(fails)

	// Goroutine for signal handling
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case sig := <-sigCh:
			fmt.Printf("SHFU Service received signal: %v, shutting down gracefully...\n", sig)
			cancel()
		case <-ctx.Done():
			// Context was cancelled for other reasons
		}
	}()

	// Start updater goroutines for each chain pair
	for _, chainPair := range srv.ChainPairs {
		wg.Add(1)
		go func(pair *SHFUChainPair) {
			defer wg.Done()
			err := srv.runUpdaterForChainPair(ctx, pair)
			if err != nil {
				fails <- fmt.Errorf("updater for chain %s failed: %w", pair.TargetChain.ChainID(), err)
			}
		}(chainPair)
	}

	// Start gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunGRPCServer(ctx)
		if err != nil {
			fails <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	// Error handling goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range fails {
			fmt.Println("error received. stopping...")
			fmt.Printf("error details: %+v\n", e)
			cancel()
		}
	}()

	<-ctx.Done()
	srv.GracefulStop(ctx)
}

func (srv *SHFUService) runUpdaterForChainPair(ctx context.Context, chainPair *SHFUChainPair) error {
	ticker := time.NewTicker(srv.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := srv.executeUpdateForChainPair(ctx, chainPair); err != nil {
				fmt.Printf("SHFU update failed for chain %s: %v\n", chainPair.TargetChain.ChainID(), err)
				return err // Return error to stop the service when no records found
			}
		}
	}
}

func (srv *SHFUService) executeUpdateForChainPair(ctx context.Context, chainPair *SHFUChainPair) error {
	// Get the latest record to determine the fromHeight
	latestRecord, err := srv.Storage.GetLatestSHFUForChain(ctx, chainPair.TargetChain.ChainID(), chainPair.CounterpartyChain.ChainID())
	if err != nil {
		return fmt.Errorf("failed to get latest SHFU record for chain %s: %w", chainPair.TargetChain.ChainID(), err)
	}

	if latestRecord == nil {
		return fmt.Errorf("no previous SHFU records found for chain %s: cannot determine starting height", chainPair.TargetChain.ChainID())
	}

	// Use the ToHeight from the latest record as the new fromHeight
	fromHeight := clienttypes.Height{
		RevisionNumber: latestRecord.ToHeight.RevisionNumber,
		RevisionHeight: latestRecord.ToHeight.RevisionHeight,
	}

	// Execute SHFU and store the result with both target and counterparty chains
	record, err := SHFUExecuteAndStore(ctx, chainPair.TargetChain, chainPair.CounterpartyChain, fromHeight, srv.Storage)
	if err != nil {
		return fmt.Errorf("failed to execute SHFU for chain %s: %w", chainPair.TargetChain.ChainID(), err)
	}

	if record != nil {
		fmt.Printf("SHFU executed successfully for chain %s (counterparty: %s), from height %d-%d to height %d-%d\n",
			record.ChainID,
			chainPair.CounterpartyChain.ChainID(),
			record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight,
			record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight)
	}

	return nil
}

// Backward compatibility: keep old methods for single chain use
func (srv *SHFUService) RunUpdater(ctx context.Context) error {
	// Use the first chain pair for backward compatibility
	if len(srv.ChainPairs) == 0 {
		return fmt.Errorf("no chain pairs configured")
	}
	return srv.runUpdaterForChainPair(ctx, srv.ChainPairs[0])
}

func (srv *SHFUService) executeUpdate(ctx context.Context) error {
	// Use the first chain pair for backward compatibility
	if len(srv.ChainPairs) == 0 {
		return fmt.Errorf("no chain pairs configured")
	}
	return srv.executeUpdateForChainPair(ctx, srv.ChainPairs[0])
}

func (srv *SHFUService) RunGRPCServer(ctx context.Context) error {
	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create SHFU gRPC service implementation
	grpcService := shfu_grpc.NewSHFUGRPCServer(srv.Storage)

	// Register SHFU service
	shfu_grpc.RegisterSHFUServiceServer(grpcServer, grpcService)

	// Create listener
	lis, err := net.Listen("tcp", srv.GRPCAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", srv.GRPCAddr, err)
	}

	fmt.Printf("Starting SHFU gRPC server on %s\n", srv.GRPCAddr)

	// Start server in a goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	fmt.Println("Stopping SHFU gRPC server...")
	grpcServer.GracefulStop()

	return nil
}

func (*SHFUService) GracefulStop(ctx context.Context) {
}

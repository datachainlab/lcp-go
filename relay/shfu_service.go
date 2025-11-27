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

	"github.com/datachainlab/lcp-go/relay/shfu_grpc"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	"google.golang.org/grpc"
)

const DefaultPollInterval = 10 * time.Second
const MinCleanupInterval = 10 * time.Minute

// SHFUChainPair represents a target chain and its counterparty chain pair
type SHFUChainPair struct {
	TargetChain       *core.ProvableChain
	CounterpartyChain *core.ProvableChain
}

type SHFUService struct {
	Storage        SHFUStorage
	ChainPairs     []*SHFUChainPair // Changed from TargetChains to ChainPairs
	PollInterval   time.Duration
	GRPCAddr       string        // gRPC server address (e.g., ":8080")
	CleanupAge     time.Duration // Cleanup age threshold for old records, must be >= MinCleanupInterval to enable
	TargetChainIDs []string      // Target chain IDs for logging
}

// NewSHFUService creates a new SHFUService
func NewSHFUService(storage SHFUStorage, chainPairs []*SHFUChainPair, grpcAddr string, pollInterval time.Duration, cleanupAge time.Duration, targetChainIDs []string) *SHFUService {
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	return &SHFUService{
		Storage:        storage,
		ChainPairs:     chainPairs,
		PollInterval:   pollInterval,
		GRPCAddr:       grpcAddr,
		CleanupAge:     cleanupAge,
		TargetChainIDs: targetChainIDs,
	}
}

func (srv *SHFUService) SHFUServiceRun(ctx context.Context) {
	// Log service startup information
	srv.getLogger().InfoContext(ctx, "Starting SHFU Service",
		"chains", srv.TargetChainIDs,
		"database", srv.Storage.Description(),
		"grpc_address", srv.GRPCAddr,
		"poll_interval", srv.PollInterval)
	srv.getLogger().InfoContext(ctx, "Press Ctrl+C to stop the service")

	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		srv.getLogger().InfoContext(ctx, "SHFU Service stopped")
	}()

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
			srv.getLogger().InfoContext(ctx, "SHFU Service received signal, shutting down gracefully", "signal", sig)
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
		err := srv.runGRPCServer(ctx)
		if err != nil {
			fails <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	// Start cleanup goroutine if CleanupAge is configured with minimum interval
	if srv.CleanupAge >= MinCleanupInterval {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := srv.runCleanup(ctx)
			if err != nil {
				fails <- fmt.Errorf("cleanup routine failed: %w", err)
			}
		}()
	}

	// Error handling goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range fails {
			srv.getLogger().ErrorContext(ctx, "error received, stopping service", e)
			cancel()
		}
	}()

	<-ctx.Done()
	srv.GracefulStop(ctx)
}

func (srv *SHFUService) runUpdaterForChainPair(ctx context.Context, chainPair *SHFUChainPair) error {
	ticker := time.NewTicker(srv.PollInterval)
	defer ticker.Stop()

	consecutiveErrors := 0
	const maxConsecutiveErrors = 10

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			// Execute SHFU and store the result with both target and counterparty chains
			_, err := SHFUExecuteAndStore(ctx, chainPair.TargetChain, chainPair.CounterpartyChain, srv.Storage)
			if err != nil {
				consecutiveErrors++
				srv.getLogger().ErrorContext(ctx, "SHFU update failed", err,
					"chain_id", chainPair.TargetChain.ChainID(),
					"consecutive_errors", consecutiveErrors,
					"max_errors", maxConsecutiveErrors)

				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("failed to execute SHFU for chain %s after %d consecutive errors: %w",
						chainPair.TargetChain.ChainID(), maxConsecutiveErrors, err)
				}
			} else {
				// Reset consecutive error count on success
				if consecutiveErrors > 0 {
					srv.getLogger().InfoContext(ctx, "SHFU update succeeded after recovery",
						"chain_id", chainPair.TargetChain.ChainID(),
						"recovered_after_errors", consecutiveErrors)
				}
				consecutiveErrors = 0
			}
		}
	}
}

func (srv *SHFUService) runGRPCServer(ctx context.Context) error {
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

	srv.getLogger().InfoContext(ctx, "Starting SHFU gRPC server", "address", srv.GRPCAddr)

	// Start server in a goroutine
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			srv.getLogger().ErrorContext(ctx, "gRPC server error", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	srv.getLogger().InfoContext(ctx, "Stopping SHFU gRPC server")
	grpcServer.GracefulStop()

	return nil
}

// runCleanup periodically runs the CleanupOldSHFU operation
func (srv *SHFUService) runCleanup(ctx context.Context) error {
	// Run cleanup every 5 minutes
	cleanupInterval := 5 * time.Minute
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	consecutiveErrors := 0
	const maxConsecutiveErrors = 10000

	srv.getLogger().InfoContext(ctx, "Started SHFU cleanup routine",
		"cleanup_age", srv.CleanupAge.String(),
		"cleanup_interval", cleanupInterval.String())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			deletedCount, err := srv.Storage.CleanupOldSHFU(ctx, srv.CleanupAge)
			if err != nil {
				consecutiveErrors++
				srv.getLogger().ErrorContext(ctx, "Cleanup failed", err,
					"consecutive_errors", consecutiveErrors,
					"max_errors", maxConsecutiveErrors)

				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("cleanup failed after %d consecutive errors: %w",
						maxConsecutiveErrors, err)
				}
			} else {
				// Reset consecutive error count on success
				if consecutiveErrors > 0 {
					srv.getLogger().InfoContext(ctx, "Cleanup recovered after errors",
						"recovered_after_errors", consecutiveErrors)
				}
				consecutiveErrors = 0

				if deletedCount > 0 {
					srv.getLogger().InfoContext(ctx, "Cleanup completed",
						"deleted_count", deletedCount)
				}
			}
		}
	}
}

func (*SHFUService) GracefulStop(ctx context.Context) {
}

// getLogger returns a logger for SHFU service with appropriate module name
func (srv *SHFUService) getLogger() *log.RelayLogger {
	return log.GetLogger().WithModule("shfu-service")
}

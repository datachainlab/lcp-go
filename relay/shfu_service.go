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
	Storage          SHFUStorage
	ChainPairs       []*SHFUChainPair // Changed from TargetChains to ChainPairs
	PollInterval     time.Duration
	GRPCAddr         string        // gRPC server address (e.g., ":8080")
	CleanupOlderThan time.Duration // Cleanup interval and age threshold for old records, must be >= MinCleanupInterval to enable
}

// NewSHFUService creates a new SHFUService
func NewSHFUService(storage SHFUStorage, chainPairs []*SHFUChainPair, grpcAddr string, cleanupOlderThan time.Duration) *SHFUService {
	return &SHFUService{
		Storage:          storage,
		ChainPairs:       chainPairs,
		PollInterval:     DefaultPollInterval,
		GRPCAddr:         grpcAddr,
		CleanupOlderThan: cleanupOlderThan,
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

	// Start cleanup goroutine if CleanupOlderThan is configured with minimum interval
	if srv.CleanupOlderThan >= MinCleanupInterval {
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
				fmt.Printf("SHFU update failed for chain %s (consecutive errors: %d/%d): %v\n",
					chainPair.TargetChain.ChainID(), consecutiveErrors, maxConsecutiveErrors, err)

				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("failed to execute SHFU for chain %s after %d consecutive errors: %w",
						chainPair.TargetChain.ChainID(), maxConsecutiveErrors, err)
				}
			} else {
				// Reset consecutive error count on success
				if consecutiveErrors > 0 {
					fmt.Printf("SHFU update succeeded for chain %s (recovered after %d consecutive errors)\n",
						chainPair.TargetChain.ChainID(), consecutiveErrors)
				}
				consecutiveErrors = 0
			}
		}
	}
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

// runCleanup periodically runs the CleanupOldSHFU operation
func (srv *SHFUService) runCleanup(ctx context.Context) error {
	// Run cleanup every 5 minutes
	cleanupInterval := 5 * time.Minute
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	consecutiveErrors := 0
	const maxConsecutiveErrors = 10000

	fmt.Printf("Started SHFU cleanup routine: cleaning records older than %v, running every %v\n",
		srv.CleanupOlderThan, cleanupInterval)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			deletedCount, err := srv.Storage.CleanupOldSHFU(ctx, srv.CleanupOlderThan)
			if err != nil {
				consecutiveErrors++
				fmt.Printf("Cleanup failed (consecutive errors: %d/%d): %v\n",
					consecutiveErrors, maxConsecutiveErrors, err)

				if consecutiveErrors >= maxConsecutiveErrors {
					return fmt.Errorf("cleanup failed after %d consecutive errors: %w",
						maxConsecutiveErrors, err)
				}
			} else {
				// Reset consecutive error count on success
				if consecutiveErrors > 0 {
					fmt.Printf("Cleanup recovered after %d consecutive errors\n", consecutiveErrors)
				}
				consecutiveErrors = 0

				if deletedCount > 0 {
					fmt.Printf("Cleanup completed: deleted %d old SHFU records\n", deletedCount)
				}
			}
		}
	}
}

func (*SHFUService) GracefulStop(ctx context.Context) {
}

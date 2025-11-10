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

type SHFUService struct {
	Storage      SHFUStorage
	TargetChains []*core.ProvableChain // Changed from single chain to multiple chains
	PollInterval time.Duration
	GRPCAddr     string // gRPC server address (e.g., ":8080")
}

// NewSHFUService creates a new SHFUService
func NewSHFUService(storage SHFUStorage, targetChains []*core.ProvableChain, grpcAddr string) *SHFUService {
	return &SHFUService{
		Storage:      storage,
		TargetChains: targetChains,
		PollInterval: 30 * time.Second, // Default 30 seconds polling interval
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
	failBufferSize := 1 + len(srv.TargetChains) + 1
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

	// Start a single updater goroutine that handles all chains sequentially
	wg.Add(1)
	go func() {
		defer wg.Done()
		
		ticker := time.NewTicker(srv.PollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Process each chain sequentially in a single goroutine
				for _, targetChain := range srv.TargetChains {
					select {
					case <-ctx.Done():
						return
					default:
						if err := srv.executeUpdateForChain(ctx, targetChain); err != nil {
							fmt.Printf("SHFU update failed for chain %s: %v\n", targetChain.ChainID(), err)
							// Continue with other chains instead of failing
							continue
						}
					}
				}
			}
		}
	}()

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

func (srv *SHFUService) runUpdaterForChain(ctx context.Context, targetChain *core.ProvableChain) error {
	ticker := time.NewTicker(srv.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := srv.executeUpdateForChain(ctx, targetChain); err != nil {
				fmt.Printf("SHFU update failed for chain %s: %v\n", targetChain.ChainID(), err)
				return err // Return error to stop the service when no records found
			}
		}
	}
}

func (srv *SHFUService) executeUpdateForChain(ctx context.Context, targetChain *core.ProvableChain) error {
	// Get the latest record to determine the fromHeight
	latestRecord, err := srv.Storage.GetLatestSHFUForChain(ctx, targetChain.ChainID())
	if err != nil {
		return fmt.Errorf("failed to get latest SHFU record for chain %s: %w", targetChain.ChainID(), err)
	}

	if latestRecord == nil {
		return fmt.Errorf("no previous SHFU records found for chain %s: cannot determine starting height", targetChain.ChainID())
	}

	// Use the ToHeight from the latest record as the new fromHeight
	fromHeight := clienttypes.Height{
		RevisionNumber: latestRecord.ToHeight.RevisionNumber,
		RevisionHeight: latestRecord.ToHeight.RevisionHeight,
	}

	// Execute SHFU and store the result
	record, err := SHFUExecuteAndStore(ctx, targetChain, fromHeight, srv.Storage)
	if err != nil {
		return fmt.Errorf("failed to execute SHFU for chain %s: %w", targetChain.ChainID(), err)
	}

	if record != nil {
		fmt.Printf("SHFU executed successfully for chain %s, from height %d-%d to height %d-%d\n",
			record.ChainID,
			record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight,
			record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight)
	}

	return nil
}

// Backward compatibility: keep old methods for single chain use
func (srv *SHFUService) RunUpdater(ctx context.Context) error {
	// Use the first chain for backward compatibility
	if len(srv.TargetChains) == 0 {
		return fmt.Errorf("no target chains configured")
	}
	return srv.runUpdaterForChain(ctx, srv.TargetChains[0])
}

func (srv *SHFUService) executeUpdate(ctx context.Context) error {
	// Use the first chain for backward compatibility
	if len(srv.TargetChains) == 0 {
		return fmt.Errorf("no target chains configured")
	}
	return srv.executeUpdateForChain(ctx, srv.TargetChains[0])
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

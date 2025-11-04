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
	TargetChain  *core.ProvableChain
	PollInterval time.Duration
	GRPCAddr     string // gRPC server address (e.g., ":8080")
}

// NewSHFUService creates a new SHFUService with default polling interval
func NewSHFUService(storage SHFUStorage, targetChain *core.ProvableChain) *SHFUService {
	return &SHFUService{
		Storage:      storage,
		TargetChain:  targetChain,
		PollInterval: 30 * time.Second, // Default 30 seconds polling interval
		GRPCAddr:     "",               // Will be set by command line flag
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

	fails := make(chan error, 3) // Buffer size of 3 for signal handling
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

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunUpdater(ctx)
		if err != nil {
			fails <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunGRPCServer(ctx)
		if err != nil {
			fails <- err
		}
	}()

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
	//slog.Info("stopping...")

	srv.GracefulStop(ctx) //only used context value
}

func (srv *SHFUService) RunUpdater(ctx context.Context) error {
	ticker := time.NewTicker(srv.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := srv.executeUpdate(ctx); err != nil {
				fmt.Printf("SHFU update failed: %v\n", err)
				return err // Return error to stop the service when no records found
			}
		}
	}
}

func (srv *SHFUService) executeUpdate(ctx context.Context) error {
	// Get the latest record to determine the fromHeight
	latestRecord, err := srv.Storage.GetLatestSHFUForChain(ctx, srv.TargetChain.ChainID())
	if err != nil {
		return fmt.Errorf("failed to get latest SHFU record: %w", err)
	}

	if latestRecord == nil {
		return fmt.Errorf("no previous SHFU records found for chain %s: cannot determine starting height", srv.TargetChain.ChainID())
	}

	// Use the ToHeight from the latest record as the new fromHeight
	fromHeight := clienttypes.Height{
		RevisionNumber: latestRecord.ToHeight.RevisionNumber,
		RevisionHeight: latestRecord.ToHeight.RevisionHeight,
	}

	// Execute SHFU and store the result
	record, err := SHFUExecuteAndStore(ctx, srv.TargetChain, fromHeight, srv.Storage)
	if err != nil {
		return fmt.Errorf("failed to execute SHFU: %w", err)
	}

	if record != nil {
		fmt.Printf("SHFU executed successfully for chain %s, from height %d-%d to height %d-%d\n",
			record.ChainID,
			record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight,
			record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight)
	}

	return nil
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

package relay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/config"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	// SHFU flags
	flagSQLitePath     = "sqlite_path"
	flagGRPCAddr       = "grpc_addr"
	flagUpdateInterval = "update_interval"
	flagCacheSize      = "cache_size"
)

// UpdateClientCacheCmd creates the update-client-cache command (alias for shfu)
func UpdateClientCacheCmd(ctx *config.Context) *cobra.Command {
	return SHFUCacheCmd(ctx)
}

// SHFUCacheCmd creates the shfu command with subcommands
func SHFUCacheCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shfu",
		Short: "SHFU management commands",
	}

	cmd.AddCommand(
		dbInitCmd(ctx),
		serverCmd(ctx),
		updateCmd(ctx),
		queryChainCmd(ctx),
		dbListCmd(ctx),
		dbGetCmd(ctx),
	)
	return cmd
}

// dbListCmd lists all SHFU records in the database
func dbListCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dblist",
		Short: "List all SHFU records in the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite_path flag)")
			}

			storage, err := shfu_storage.OpenSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer storage.Close()

			records, err := storage.ListAllSHFURecords(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to list SHFU records: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No SHFU records found.")
				return nil
			}

			fmt.Printf("%-24s %-24s %-16s %-16s %-24s\n", "chain_id", "counterparty_chain_id", "from_height", "to_height", "to_height_time")
			for _, r := range records {
				fmt.Printf("%-24s %-24s %d-%d           %d-%d           %s\n",
					r.ChainID,
					r.CounterpartyChainID,
					r.FromHeight.RevisionNumber, r.FromHeight.RevisionHeight,
					r.ToHeight.RevisionNumber, r.ToHeight.RevisionHeight,
					r.ToHeightTime.Format(time.RFC3339),
				)
			}
			return nil
		},
	}
	cmd.Flags().String(flagSQLitePath, "", "Path to SQLite database file")
	return cmd
}

// parseUint64Arg parses a uint64 argument and returns an error if invalid
func parseUint64Arg(s string, name string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value for %s: %s", name, s)
	}
	return v, nil
}

// parseHeightArg parses a height argument in "<revision>-<height>" format
func parseHeightArg(s string, name string) (ibcexported.Height, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid %s format: expected '<revision>-<height>', got '%s'", name, s)
	}

	// Parse revision number
	revisionNumber, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid revision in %s: %s", name, parts[0])
	}

	// Parse height
	revisionHeight, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid height in %s: %s", name, parts[1])
	}

	return clienttypes.Height{
		RevisionNumber: revisionNumber,
		RevisionHeight: revisionHeight,
	}, nil
}

// parseHeightArgOptional parses height argument, returning nil if empty string
func parseHeightArgOptional(s string, name string) (*ibcexported.Height, error) {
	if s == "" {
		return nil, nil
	}

	height, err := parseHeightArg(s, name)
	if err != nil {
		return nil, err
	}

	return &height, nil
}

// dbGetCmd gets SHFU records by chainId, counterpartyChainId, fromHeight, toHeight
func dbGetCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dbget <path-name:chain-id> <from-height> <to-height>",
		Short: "Get SHFU records by path:chain, fromHeight, toHeight (heights in <revision>-<height> format)",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite_path flag)")
			}

			// Parse path:chain format
			pathName, chainID, err := parsePathChainArg(args[0])
			if err != nil {
				return err
			}

			// Get target chain and counterparty chain using getChainPairFromPath
			_, counterpartyChain, err := getChainPairFromPath(ctx, pathName, chainID)
			if err != nil {
				return fmt.Errorf("failed to get chain '%s' from path '%s': %w", chainID, pathName, err)
			}

			fromHeight, err := parseHeightArg(args[1], "from-height")
			if err != nil {
				return err
			}
			toHeight, err := parseHeightArg(args[2], "to-height")
			if err != nil {
				return err
			}

			storage, err := shfu_storage.OpenSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}

			defer storage.Close()

			records, err := storage.FindSHFUByChainAndHeight(cmd.Context(), chainID, counterpartyChain.ChainID(), fromHeight, toHeight)
			if err != nil {
				return fmt.Errorf("failed to query SHFU records: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No SHFU records found.")
				return nil
			}

			for _, r := range records {
				printSHFURecordSummary(r)
			}
			return nil
		},
	}
	cmd.Flags().String(flagSQLitePath, "", "Path to SQLite database file")
	return cmd
}

// PrintSHFURecordSummary prints a detailed summary of the SHFU record
func printSHFURecordSummary(record *SHFURecord) {
	results := record.UpdateClientResults
	fmt.Printf("Received %d updateClient results\n", len(results))
	for i, result := range results {
		fmt.Printf("Result %d: message_size=%d bytes, signature_size=%d bytes\n",
			i+1,
			len(result.Message),
			len(result.Signature))
		fmt.Printf("  Message (hex): %s\n", hex.EncodeToString(result.Message))
		fmt.Printf("  Signature (hex): %s\n", hex.EncodeToString(result.Signature))
	}

	// Prepare update client results for JSON output
	updateClientResults := make([]map[string]interface{}, len(results))
	for i, result := range results {
		updateClientResults[i] = map[string]interface{}{
			"message_hex":    hex.EncodeToString(result.Message),
			"signature_hex":  hex.EncodeToString(result.Signature),
			"message_size":   len(result.Message),
			"signature_size": len(result.Signature),
		}
	}

	resultSummary := map[string]interface{}{
		"chain_id":               record.ChainID,
		"from_height":            record.FromHeight,
		"to_height":              record.ToHeight,
		"to_height_time":         record.ToHeightTime.Format(time.RFC3339),
		"results_received_count": len(results),
		"update_client_results":  updateClientResults,
		"timestamp":              time.Now().Format(time.RFC3339),
	}

	resultBytes, err := json.MarshalIndent(resultSummary, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal result to JSON: %w\n", err)
	} else {
		fmt.Printf("SetupHeadersForUpdate result:\n%s\n", string(resultBytes))
	}
}

func dbInitCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dbinit",
		Short: "Initialize SHFU database",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get database path from flag
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite_path flag)")
			}

			fmt.Printf("Initializing database at: %s\n", dbPath)

			// Create storage factory and initialize database
			storage, err := shfu_storage.InitSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to create storage: %w", err)
			}
			defer storage.Close()

			fmt.Printf("Database initialized successfully at: %s\n", dbPath)

			return nil
		},
	}

	// Add database path flag
	cmd.Flags().String(flagSQLitePath, "", "Path to SQLite database file")

	return cmd
}

func serverCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server <path-name:chain-id> [path-name:chain-id...]",
		Short: "Start SetupHeadersForUpdate SHFU server for one or more path:chain combinations",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get SQLite database path
			dbPath, err := cmd.Flags().GetString(flagSQLitePath)
			if err != nil {
				return fmt.Errorf("failed to get SQLite path: %w", err)
			}
			if dbPath == "" {
				return fmt.Errorf("SQLite database path is required (use --%s flag)", flagSQLitePath)
			}

			// Get gRPC server address
			grpcAddr, err := cmd.Flags().GetString(flagGRPCAddr)
			if err != nil {
				return fmt.Errorf("failed to get gRPC address: %w", err)
			}

			// Open storage
			storage, err := shfu_storage.OpenSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer storage.Close()

			// Parse path:chain arguments and create chain pairs
			chainPairs := make([]*SHFUChainPair, len(args))
			targetChainIDs := make([]string, len(args))
			for i, arg := range args {
				// Parse path:chain format
				pathName, chainID, err := parsePathChainArg(arg)
				if err != nil {
					return err
				}

				// Get target chain and counterparty chain using getChainPairFromPath
				targetChain, counterpartyChain, err := getChainPairFromPath(ctx, pathName, chainID)
				if err != nil {
					return fmt.Errorf("failed to get chain '%s' from path '%s': %w", chainID, pathName, err)
				}

				chainPairs[i] = &SHFUChainPair{
					TargetChain:       targetChain,
					CounterpartyChain: counterpartyChain,
				}
				targetChainIDs[i] = chainID
			}

			// Create and start multi-chain SHFU service
			service := NewSHFUService(storage, chainPairs, grpcAddr)

			fmt.Printf("Starting SHFU Service for chains: %v...\n", targetChainIDs)
			fmt.Printf("Database: %s\n", dbPath)
			fmt.Printf("gRPC server address: %s\n", service.GRPCAddr)
			fmt.Printf("Polling interval: %v\n", service.PollInterval)
			fmt.Println("Press Ctrl+C to stop the service")

			// Start the service (this will block until stopped)
			service.SHFUServiceRun(cmd.Context())

			fmt.Println("SHFU Service stopped")
			return nil
		},
	}
	cmd = dbPathFlag(cmd)
	cmd = grpcAddrFlag(cmd)
	return cmd
}

func updateCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update --sqlite_path <sqlite file path> <path-name:chain-id> <from-height>",
		Short: "Execute SHFU (SetupHeadersForUpdate) for specified chain and save results to database",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("path:chain and from-height are required")
			}

			// Parse path:chain format
			pathName, targetChainID, err := parsePathChainArg(args[0])
			if err != nil {
				return err
			}
			fromHeightArg := args[1]

			// Parse from-height argument (returns nil if empty string)
			fromHeight, err := parseHeightArgOptional(fromHeightArg, "from-height")
			if err != nil {
				return err
			}

			// Get target chain and counterparty chain using getChainPairFromPath
			targetChain, counterpartyChain, err := getChainPairFromPath(ctx, pathName, targetChainID)
			if err != nil {
				return fmt.Errorf("failed to get chain '%s' from path '%s': %w", targetChainID, pathName, err)
			}

			// Get database path from flag
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite_path flag)")
			}

			// Open existing database connection
			storage, err := shfu_storage.OpenSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer storage.Close()

			// Execute SHFU for the target chain with counterparty chain
			record, err := SHFUExecuteAndStore(cmd.Context(), targetChain, counterpartyChain, fromHeight, storage)
			if err != nil {
				return fmt.Errorf("failed to execute and store SHFU for target chain: %w", err)
			}

			fmt.Printf("Successfully executed SHFU for chain %s:\n", targetChainID)

			// Print detailed summary for target chain
			if record == nil {
				fmt.Printf("No new SHFU record created for %s\n", targetChain.ChainID())
			} else {
				printSHFURecordSummary(record)
			}

			return nil
		},
	}

	// Add database path flag
	cmd.Flags().String(flagSQLitePath, "", "Path to SQLite database file")

	return cmd
}

func queryChainCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query-chain <path-name:chain-id>",
		Short: "Query chain information including latest consensus state",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Parse path:chain format
			pathName, targetChainID, err := parsePathChainArg(args[0])
			if err != nil {
				return err
			}

			target, _, err := getChainPairFromPath(ctx, pathName, targetChainID)
			if err != nil {
				return err
			}

			// Get the path configuration to extract channel ID
			path, exists := ctx.Config.Paths[pathName]
			if !exists {
				return fmt.Errorf("path '%s' not found in configuration", pathName)
			}

			// Determine the channel ID based on the chain ID and path configuration
			var channelID string
			if path.Src.ChainID == targetChainID {
				channelID = path.Src.ChannelID
			} else if path.Dst.ChainID == targetChainID {
				channelID = path.Dst.ChannelID
			} else {
				return fmt.Errorf("chain ID '%s' not found in path '%s' configuration", targetChainID, pathName)
			}

			// Get the latest height from the target chain
			latestHeight, err := target.LatestHeight(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get latest height: %w", err)
			}

			// Try to get the finalized header
			latestFinalizedHeader, err := target.GetLatestFinalizedHeader(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get latest finalized header: %w", err)
			}

			var latestConsensusInfo interface{}

			// Try to query the client state using yui-relayer's QueryClientState
			// This uses the target chain's own RPC client instead of cosmos-sdk's offline client
			qctx := core.NewQueryContext(cmd.Context(), latestHeight)
			if clientStateRes, err := target.QueryClientState(qctx); err != nil {
				// If QueryClientState fails, just note the error but continue
				latestConsensusInfo = map[string]interface{}{
					"error": err.Error(),
					"note":  "Failed to query client state from yui-relayer",
				}
			} else {
				// Unpack the ClientState from Any using target chain's codec
				var clientState ibcexported.ClientState
				if err := target.Codec().UnpackAny(clientStateRes.ClientState, &clientState); err != nil {
					latestConsensusInfo = map[string]interface{}{
						"error": fmt.Sprintf("Failed to unpack client state: %v", err),
						"note":  "Could not decode ClientState from Any",
					}
				} else {
					// Extract information from the unpacked client state
					latestHeight := clientState.GetLatestHeight()
					latestConsensusInfo = map[string]interface{}{
						"proof_height": clientStateRes.ProofHeight,
						"client_state_info": map[string]interface{}{
							"chain_id":          pathName,
							"channel_id":        channelID,
							"client_state_type": fmt.Sprintf("%T", clientState),
							"latest_height_from_client": map[string]interface{}{
								"revision_number":        latestHeight.GetRevisionNumber(),
								"revision_height":        latestHeight.GetRevisionHeight(),
								"revision_number_height": fmt.Sprintf("%d-%d", latestHeight.GetRevisionNumber(), latestHeight.GetRevisionHeight()),
							},
							"latest_height_from_proof": map[string]interface{}{
								"revision_number": clientStateRes.ProofHeight.RevisionNumber,
								"revision_height": clientStateRes.ProofHeight.RevisionHeight,
							},
						},
					}
				}
			}

			result := map[string]interface{}{
				"chain_id":                       target.ChainID(),
				"path_name":                      pathName,
				"channel_id":                     channelID,
				"latest_height":                  latestHeight.GetRevisionHeight(),
				"latest_finalized_header_height": latestFinalizedHeader.GetHeight().GetRevisionHeight(),
				"latest_consensus_state":         latestConsensusInfo,
				"message":                        "Chain information displayed with LatestConsensusState and path info",
				"success":                        true,
				"timestamp":                      time.Now().Format(time.RFC3339),
			}

			// Convert result to JSON string and output
			resultBytes, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result to JSON: %w", err)
			}

			fmt.Println(string(resultBytes))
			return nil
		},
	}
	return cmd
}

// Flag functions
func dbPathFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagSQLitePath, "", "path to SQLite database file")
	if err := viper.BindPFlag(flagSQLitePath, cmd.Flags().Lookup(flagSQLitePath)); err != nil {
		panic(err)
	}
	return cmd
}

func grpcAddrFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagGRPCAddr, ":8080", "gRPC server address (default: :8080)")
	if err := viper.BindPFlag(flagGRPCAddr, cmd.Flags().Lookup(flagGRPCAddr)); err != nil {
		panic(err)
	}
	return cmd
}

func updateIntervalFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Duration(flagUpdateInterval, 0, "automatic update interval")
	if err := viper.BindPFlag(flagUpdateInterval, cmd.Flags().Lookup(flagUpdateInterval)); err != nil {
		panic(err)
	}
	return cmd
}

func cacheSizeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Int(flagCacheSize, 0, "memory cache size")
	if err := viper.BindPFlag(flagCacheSize, cmd.Flags().Lookup(flagCacheSize)); err != nil {
		panic(err)
	}
	return cmd
}

// getChainPairFromPath returns a pair of chain objects from the given IBC path name and target chain ID
// The target chain is returned as the first element, and the counterparty chain as the second element
func getChainPairFromPath(ctx *config.Context, pathName string, targetChainID string) (*core.ProvableChain, *core.ProvableChain, error) {
	// Get the path configuration
	path, err := ctx.Config.Paths.Get(pathName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get path %s: %w", pathName, err)
	}

	srcChain, err := ctx.Config.GetChain(path.Src.ChainID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get source chain %s: %w", path.Src.ChainID, err)
	}

	dstChain, err := ctx.Config.GetChain(path.Dst.ChainID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get destination chain %s: %w", path.Dst.ChainID, err)
	}

	if targetChainID == path.Src.ChainID {
		return srcChain, dstChain, nil
	} else if targetChainID == path.Dst.ChainID {
		return dstChain, srcChain, nil
	} else {
		return nil, nil, fmt.Errorf("target chain ID %s is not part of path %s", targetChainID, pathName)
	}
}

// parsePathChainArg parses "path:chain" format argument and returns the path name and chain ID
func parsePathChainArg(arg string) (pathName string, chainID string, err error) {
	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid argument format '%s': expected 'path-name:chain-id'", arg)
	}
	return parts[0], parts[1], nil
}

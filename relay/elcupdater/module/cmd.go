package module

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/hyperledger-labs/yui-relayer/config"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/coreutil"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	lcp "github.com/datachainlab/lcp-go/relay"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
)

const (
	// flags
	flagSQLitePath          = "sqlite-path"
	flagGRPCAddr            = "grpc-addr"
	flagUpdateInterval      = "update-interval"
	flagCleanupAge          = "cleanup-age"
	flagChainID             = "chain-id"
	flagCounterpartyChainID = "counterparty-chain-id"
	flagNoHeader            = "no-header"
)

// ElcUpdaterCmd creates the elc-updater subcommand
func ElcUpdaterCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "elc-updater",
		Short: "ELC updater management commands",
	}

	cmd.AddCommand(
		dbInitCmd(ctx),
		dbListCmd(ctx),
		dbGetCmd(ctx),
		dbCleanupCmd(ctx),
		updateCmd(ctx),
		serverCmd(ctx),
		queryChainCmd(ctx),
	)
	return cmd
}

func dbInitCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dbinit",
		Short: "Initialize ELC updater database",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get database path from flag
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite-path flag)")
			}

			fmt.Printf("Initializing database at: %s\n", dbPath)

			// Create storage factory and initialize database
			sto, err := elcupdater_storage.InitSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to create storage: %w", err)
			}
			defer sto.Close()
			fmt.Printf("Database initialized successfully at: %s\n", dbPath)

			return nil
		},
	}

	bindPFlagDbPath(cmd)
	return cmd
}

// dbListCmd lists all ELC updater records in the database
func dbListCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dblist",
		Short: "List all ELC updater records in the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite-path flag)")
			}

			// Get filter options
			chainID := cmd.Flag(flagChainID).Value.String()
			counterpartyChainID := cmd.Flag(flagCounterpartyChainID).Value.String()
			noHeader, _ := cmd.Flags().GetBool(flagNoHeader)

			sto, err := elcupdater_storage.OpenSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer sto.Close()

			records, err := sto.List(cmd.Context(), chainID, counterpartyChainID)
			if err != nil {
				return fmt.Errorf("failed to list ELC updater records: %w", err)
			}

			// Print header unless --no-header is specified
			if !noHeader {
				fmt.Printf("%-24s %-24s %-16s %-16s %s\n", "chain_id", "cp_chain_id", "from_height", "to_height", "updated_at")
			}

			for _, r := range records {
				fmt.Printf("%-24s %-24s %-16s %-16s %s\n",
					r.ChainID,
					r.CounterpartyChainID,
					fmt.Sprintf("%d-%d", r.FromHeight.RevisionNumber, r.FromHeight.RevisionHeight),
					fmt.Sprintf("%d-%d", r.ToHeight.RevisionNumber, r.ToHeight.RevisionHeight), r.UpdatedAt.Format(time.RFC3339),
				)
			}
			return nil
		},
	}
	bindPFlagDbPath(cmd)
	bindPFlagChainFilter(cmd)
	bindPFlagNoHeader(cmd)
	return cmd
}

// dbGetCmd gets ELCUpdateRecords by chainId, counterpartyChainId, toHeight
func dbGetCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "dbget <path-name:chain-id> <from-height> <to-height>",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite-path flag)")
			}

			// Parse path:chain format and get chains
			chainPair, err := parsePathChainArg(ctx, args[0])
			if err != nil {
				return err
			}

			fromHeight, err := parseHeightArg(args[1], "from-height")
			if err != nil {
				return err
			}

			toHeight, err := parseHeightArg(args[2], "to-height")
			if err != nil {
				return err
			}

			sto, err := elcupdater_storage.OpenSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}

			defer sto.Close()

			// Use zero height for fromHeight when not specified
			records, err := sto.FindByChainAndHeight(cmd.Context(), chainPair.TargetChain.ChainID(), chainPair.CounterpartyChain.ChainID(), fromHeight, toHeight)
			if err != nil {
				return fmt.Errorf("failed to query FindByChainAndHeight records: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No ELCUpdateRecords found.")
				return nil
			}

			for _, r := range records {
				summary := r.FormatSummary()
				resultBytes, err := json.MarshalIndent(summary, "", "  ")
				if err != nil {
					fmt.Printf("failed to marshal result to JSON: %v\n", err)
				} else {
					fmt.Printf("ELCUpdateRecords result:\n%s\n", string(resultBytes))
				}
			}
			return nil
		},
	}
	bindPFlagDbPath(cmd)
	return cmd
}

func dbCleanupCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dbcleanup <duration>",
		Short: "Clean up old ELC updater records from the database (duration: e.g. '7d', '24h', '30m', '600s')",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite-path flag)")
			}

			cleanupStr := args[0]
			if cleanupStr == "" || cleanupStr == "0" {
				return fmt.Errorf("cleanup duration argument is required (e.g., '7d', '24h', '30m', '600s')")
			}

			cleanupDuration, err := time.ParseDuration(cleanupStr)
			if err != nil {
				return fmt.Errorf("invalid cleanup duration format '%s': %w (examples: '7d', '24h', '30m', '600s')", cleanupStr, err)
			}

			fmt.Printf("Opening database: %s\n", dbPath)
			sto, err := elcupdater_storage.OpenSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer sto.Close()

			fmt.Printf("Cleaning up records older than: %v\n", cleanupDuration)

			deletedCount, err := sto.Cleanup(cmd.Context(), cleanupDuration)
			if err != nil {
				return fmt.Errorf("failed to cleanup old ELC updater records: %w", err)
			}

			fmt.Printf("Successfully cleaned up %d old ELC updater records\n", deletedCount)
			return nil
		},
	}

	bindPFlagDbPath(cmd)
	return cmd
}

func updateCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update --sqlite-path <sqlite file path> <path-name:chain-id>",
		Short: "Execute updateClient for specified chain and save results to database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("path:chain and from-height are required")
			}

			// Parse path:chain format and get chains
			chainPair, err := parsePathChainArg(ctx, args[0])
			if err != nil {
				return err
			}

			// Get database path from flag
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite-path flag)")
			}

			// Open existing database connection
			sto, err := elcupdater_storage.OpenSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer sto.Close()

			// Execute updateClient for the target chain with counterparty chain
			record, err := chainPair.TargetLCPProver.UpdateELCAndStore(cmd.Context(), chainPair.CounterpartyChain, sto)
			if err != nil {
				return fmt.Errorf("failed to execute UpdateELCAndStore for target chain: %w", err)
			}

			fmt.Printf("Successfully executed UpdateELCAndStore for chain %s:\n", chainPair.TargetChain.ChainID())

			// Print detailed summary for target chain
			if record == nil {
				fmt.Printf("No new ELCUpdate record created for %s\n", chainPair.TargetChain.ChainID())
			} else {
				summary := record.FormatSummary()
				resultBytes, err := json.MarshalIndent(summary, "", "  ")
				if err != nil {
					fmt.Printf("failed to marshal result to JSON: %v\n", err)
				} else {
					fmt.Printf("SetupHeadersForUpdate result:\n%s\n", string(resultBytes))
				}
			}

			return nil
		},
	}

	bindPFlagDbPath(cmd)

	return cmd
}

func serverCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server <path-name:chain-id> [path-name:chain-id]...",
		Short: "Start elc-updater server for one or more path:chain combinations",
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

			// Get update interval
			updateIntervalStr, err := cmd.Flags().GetString(flagUpdateInterval)
			if err != nil {
				return fmt.Errorf("failed to get update interval: %w", err)
			}

			var updateInterval time.Duration
			if updateIntervalStr != "" {
				updateInterval, err = time.ParseDuration(updateIntervalStr)
				if err != nil {
					return fmt.Errorf("invalid update interval format '%s': %w (examples: '10s', '1m', '5m')", updateIntervalStr, err)
				}
			}

			// Get cleanup age duration
			cleanupAgeStr, err := cmd.Flags().GetString(flagCleanupAge)
			if err != nil {
				return fmt.Errorf("failed to get cleanup age duration: %w", err)
			}

			var cleanupAge time.Duration
			if cleanupAgeStr != "" && cleanupAgeStr != "0" {
				cleanupAge, err = time.ParseDuration(cleanupAgeStr)
				if err != nil {
					return fmt.Errorf("invalid cleanup duration format '%s': %w (examples: '7d', '24h', '30m')", cleanupAgeStr, err)
				}
			}

			// Open storage
			sto, err := elcupdater_storage.OpenSQLiteStorage(cmd.Context(), dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer sto.Close()

			// Parse path:chain arguments and create chain pairs
			chainPairs := make([]ChainPair, len(args))
			targetChainIDs := make([]string, len(args))
			for i, arg := range args {
				// Parse path:chain format and get chains
				chainPair, err := parsePathChainArg(ctx, arg)
				if err != nil {
					return err
				}

				chainPairs[i] = *chainPair
				targetChainIDs[i] = chainPair.TargetChain.ChainID()
			}

			// Create and start multi-chain ELC update service
			service := NewService(sto, chainPairs, grpcAddr, updateInterval, cleanupAge, targetChainIDs)

			// Start the service (this will block until stopped)
			service.Run(cmd.Context())

			return nil
		},
	}

	bindPFlagDbPath(cmd)
	bindPFlagGRPCAddr(cmd)
	bindPFlagUpdateInterval(cmd)
	bindPFlagCleanupAge(cmd)
	return cmd
}

func queryChainCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query-chain <path-name:chain-id> [height]",
		Short: "Query chain information including latest consensus state",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			chainPair, err := parsePathChainArg(ctx, args[0])
			if err != nil {
				return err
			}
			target := chainPair.TargetChain
			channelID := target.Path().ChannelID

			// Try to get the finalized header
			latestFinalizedHeader, err := target.GetLatestFinalizedHeader(cmd.Context())
			if err != nil {
				return fmt.Errorf("failed to get latest finalized header: %w", err)
			}

			// Parse optional height argument
			var queryHeight ibcexported.Height
			if len(args) > 1 {
				// Height argument provided
				height, err := parseHeightArg(args[1], "height")
				if err != nil {
					return err
				}
				queryHeight = height
			} else {
				// No height argument - use latest height
				//latestHeight, err := target.LatestHeight(cmd.Context())
				queryHeight = latestFinalizedHeader.GetHeight()
			}

			fmt.Printf("Latest finalized header height: %d\n", latestFinalizedHeader.GetHeight().GetRevisionHeight())
			fmt.Printf("Query height: %s\n", queryHeight.String())

			var clientStateInfo interface{}
			var consensusStateInfo interface{}
			// Try to query the client state using yui-relayer's QueryClientState
			// This uses the target chain's own RPC client instead of cosmos-sdk's offline client
			qctx := core.NewQueryContext(cmd.Context(), queryHeight)
			if clientStateRes, err := target.QueryClientState(qctx); err != nil {
				// If QueryClientState fails, just note the error but continue
				clientStateInfo = map[string]interface{}{
					"error": err.Error(),
					"note":  "Failed to query client state from yui-relayer",
				}
			} else {
				// Unpack the ClientState from Any using target chain's codec
				var clientState ibcexported.ClientState
				if err := target.Codec().UnpackAny(clientStateRes.ClientState, &clientState); err != nil {
					clientStateInfo = map[string]interface{}{
						"error": fmt.Sprintf("Failed to unpack client state: %v", err),
						"note":  "Could not decode ClientState from Any",
					}
				} else {
					// Extract information from the unpacked client state
					latestHeight := clientState.GetLatestHeight()
					clientStateInfo = map[string]interface{}{
						"proof_height": clientStateRes.ProofHeight,
						"client_state_info": map[string]interface{}{
							"chain_id":          target.ChainID(),
							"channel_id":        channelID,
							"client_state_type": fmt.Sprintf("%T", clientState),
							"latest_height": map[string]interface{}{
								"revision_number": latestHeight.GetRevisionNumber(),
								"revision_height": latestHeight.GetRevisionHeight(),
							},
							"proof_height": map[string]interface{}{
								"revision_number": clientStateRes.ProofHeight.RevisionNumber,
								"revision_height": clientStateRes.ProofHeight.RevisionHeight,
							},
						},
					}
					if consensusStateRes, err := target.QueryClientConsensusState(qctx, latestHeight); err != nil {
						// If QueryClientConsensusState fails, just note the error but continue
						consensusStateInfo = map[string]interface{}{
							"error": err.Error(),
							"note":  "Failed to query consensus state from yui-relayer",
						}
					} else {
						// Unpack the ConsensusState from Any using target chain's codec
						var consensusState ibcexported.ConsensusState
						if err := target.Codec().UnpackAny(consensusStateRes.ConsensusState, &consensusState); err != nil {
							consensusStateInfo = map[string]interface{}{
								"error": fmt.Sprintf("Failed to unpack consensus state: %v", err),
								"note":  "Could not decode ConsensusState from Any",
							}
						} else {
							// Extract information from the unpacked consensus state
							consensusStateInfo = map[string]interface{}{
								"proof_height":         consensusStateRes.ProofHeight,
								"consensus_state_type": fmt.Sprintf("%T", consensusState),
							}
						}
					}
				}
			}

			result := map[string]interface{}{
				"chain_id":                       target.ChainID(),
				"channel_id":                     channelID,
				"query_height":                   fmt.Sprintf("%d-%d", queryHeight.GetRevisionNumber(), queryHeight.GetRevisionHeight()),
				"latest_finalized_header_height": latestFinalizedHeader.GetHeight().GetRevisionHeight(),
				"client_state":                   clientStateInfo,
				"consensus_state":                consensusStateInfo,
				"message":                        "Chain information displayed with LatestClientState and path info",
				"success":                        true,
				"timestamp":                      time.Now().Format(time.RFC3339),
			}
			// Convert result to JSON string and output
			resultBytes, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal result to JSON: %w", err)
			}
			fmt.Printf("Chain information with LatestConsensusState:\n%s\n", string(resultBytes))
			return nil
		},
	}
	return cmd
}

// Flag functions
func bindPFlagDbPath(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagSQLitePath, "", "path to SQLite database file")
	if err := viper.BindPFlag(flagSQLitePath, cmd.Flags().Lookup(flagSQLitePath)); err != nil {
		panic(err)
	}
	return cmd
}

func bindPFlagGRPCAddr(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagGRPCAddr, "", "gRPC server address (optional, if not specified gRPC server will not start)")
	if err := viper.BindPFlag(flagGRPCAddr, cmd.Flags().Lookup(flagGRPCAddr)); err != nil {
		panic(err)
	}
	return cmd
}

func bindPFlagUpdateInterval(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagUpdateInterval, "10s", "polling interval for updateELCAndStore (examples: '10s', '1m', '5m')")
	if err := viper.BindPFlag(flagUpdateInterval, cmd.Flags().Lookup(flagUpdateInterval)); err != nil {
		panic(err)
	}
	return cmd
}

func bindPFlagCleanupAge(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagCleanupAge, "7d", "cleanup records older than this age (examples: '7d', '24h', '30m', '600s', empty or '0' to disable)")
	if err := viper.BindPFlag(flagCleanupAge, cmd.Flags().Lookup(flagCleanupAge)); err != nil {
		panic(err)
	}
	return cmd
}

func bindPFlagChainFilter(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagChainID, "", "Filter by chain ID")
	cmd.Flags().String(flagCounterpartyChainID, "", "Filter by counterparty chain ID")
	return cmd
}

func bindPFlagNoHeader(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagNoHeader, false, "Omit table header in output")
	return cmd
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

// parsePathChainArg parses "path:chain" format argument and returns the target chain and counterparty chain
func parsePathChainArg(ctx *config.Context, arg string) (*ChainPair, error) {
	parts := strings.Split(arg, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid argument format '%s': expected 'path-name:chain-id'", arg)
	}
	pathName := parts[0]
	chainID := parts[1]

	// Use ChainsFromPath to get chains with path information properly configured
	chains, srcChainID, dstChainID, err := ctx.Config.ChainsFromPath(pathName)
	if err != nil {
		return nil, fmt.Errorf("failed to get chains from path %s: %w", pathName, err)
	}

	srcChain, _ := chains[srcChainID]
	srcProver, err := coreutil.UnwrapProver[*lcp.Prover](srcChain)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap prover for source chain %s: %w", srcChainID, err)
	}

	dstChain, _ := chains[dstChainID]
	dstProver, err := coreutil.UnwrapProver[*lcp.Prover](dstChain)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap prover for destination chain %s: %w", dstChainID, err)
	}

	if chainID == srcChainID {
		return &ChainPair{
			TargetChain:       srcChain,
			TargetLCPProver:   srcProver,
			CounterpartyChain: dstChain,
		}, nil
	} else if chainID == dstChainID {
		return &ChainPair{
			TargetChain:       dstChain,
			TargetLCPProver:   dstProver,
			CounterpartyChain: srcChain,
		}, nil
	} else {
		return nil, fmt.Errorf("target chain ID %s is not part of path %s", chainID, pathName)
	}
}

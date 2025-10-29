package relay

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
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

			fmt.Printf("%-24s %-24s %-16s %-16s %-24s\n", "chain_id", "counterparty_chain_id", "from_height", "latest_finalized_height", "latest_finalized_height_time")
			for _, r := range records {
				fmt.Printf("%-24s %-24s %d-%d           %d-%d           %s\n",
					r.ChainID,
					r.CounterpartyChainID,
					r.FromHeight.RevisionNumber, r.FromHeight.RevisionHeight,
					r.LatestFinalizedHeight.RevisionNumber, r.LatestFinalizedHeight.RevisionHeight,
					r.LatestFinalizedHeightTime.Format(time.RFC3339),
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
func parseHeightArg(s string, name string) (uint64, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid %s format: expected '<revision>-<height>', got '%s'", name, s)
	}

	// Parse revision number (we don't use it for the query, but validate it)
	_, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid revision in %s: %s", name, parts[0])
	}

	// Parse height
	height, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid height in %s: %s", name, parts[1])
	}

	return height, nil
}

// dbGetCmd gets SHFU records by chainId, counterpartyChainId, fromHeight, toHeight
func dbGetCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dbget [chain-id] [counterparty-chain-id] [from-height] [to-height]",
		Short: "Get SHFU records by chainId, counterpartyChainId, fromHeight, toHeight (heights in <revision>-<height> format)",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath := viper.GetString(flagSQLitePath)
			if dbPath == "" {
				return fmt.Errorf("database path is required (use --sqlite_path flag)")
			}

			chainID := args[0]
			counterpartyChainID := args[1]
			fromHeight, err := parseHeightArg(args[2], "from-height")
			if err != nil {
				return err
			}
			toHeight, err := parseHeightArg(args[3], "to-height")
			if err != nil {
				return err
			}

			storage, err := shfu_storage.OpenSQLiteStorage(dbPath)
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}

			defer storage.Close()

			records, err := storage.FindSHFUByChainAndHeight(cmd.Context(), chainID, counterpartyChainID, fromHeight, toHeight)
			if err != nil {
				return fmt.Errorf("failed to query SHFU records: %w", err)
			}

			if len(records) == 0 {
				fmt.Println("No SHFU records found.")
				return nil
			}

			for _, r := range records {
				PrintSHFURecordSummary(r)
			}
			return nil
		},
	}
	cmd.Flags().String(flagSQLitePath, "", "Path to SQLite database file")
	return cmd
}

// PrintSHFURecordSummary prints a detailed summary of the SHFU record
func PrintSHFURecordSummary(record *shfu_storage.SHFURecord) {
	results := record.UpdateClientResults
	fmt.Printf("Received %d updateClient results\n", len(results))
	for i, result := range results {
		fmt.Printf("Result %d: message_size=%d bytes, signature_size=%d bytes\n",
			i+1,
			len(result.Message),
			len(result.Signature))
	}

	resultSummary := map[string]interface{}{
		"chain_id":                     record.ChainID,
		"counterparty_chain_id":        record.CounterpartyChainID,
		"from_height":                  record.FromHeight,
		"latest_finalized_height":      record.LatestFinalizedHeight,
		"latest_finalized_height_time": record.LatestFinalizedHeightTime.Format(time.RFC3339),
		"results_received_count":       len(results),
		"message":                      "SHFU executed and saved to database successfully",
		"success":                      true,
		"timestamp":                    time.Now().Format(time.RFC3339),
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
		Use:   "server [chain-id]",
		Short: "Start SetupHeadersForUpdate cache server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("chain ID is required")
			}
			return nil
		},
	}
	cmd = cacheSizeFlag(updateIntervalFlag(grpcAddrFlag(dbPathFlag(cmd))))
	return cmd
}

func updateCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update --sqlite_path <sqlite file path> <ibc path>",
		Short: "Execute SHFU (SetupHeadersForUpdate) and save results to database",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("ibc path name is required")
			}

			ibcPathName := args[0]

			chains, _, _, err := ctx.Config.ChainsFromPath(ibcPathName)
			if err != nil {
				return fmt.Errorf("failed to get chains from path '%s': %w", ibcPathName, err)
			}
			// Get the path configuration to extract channel ID
			path, exists := ctx.Config.Paths[ibcPathName]
			if !exists {
				return fmt.Errorf("path '%s' not found in configuration", ibcPathName)
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

			getClientStateLatestHeight := func(chain *core.ProvableChain) (*ibcexported.Height, error) {
				// Get the latest height from the target chain
				latestHeight, err := chain.LatestHeight(cmd.Context())
				if err != nil {
					return nil, fmt.Errorf("failed to get latest height: %w", err)
				}

				qctx := core.NewQueryContext(cmd.Context(), latestHeight)
				clientStateRes, err := chain.QueryClientState(qctx)
				if err != nil {
					return nil, err
				}
				var clientState ibcexported.ClientState
				if err := chain.Codec().UnpackAny(clientStateRes.ClientState, &clientState); err != nil {
					return nil, fmt.Errorf("failed to unpack client state: %w", err)
				}
				clientLatestHeight := clientState.GetLatestHeight()
				return &clientLatestHeight, nil
			}

			// Create client.Context using cosmos-sdk's GetClientQueryContext
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return fmt.Errorf("failed to get client query context: %w", err)
			}
			_ = clientCtx // clientCtx will be used later if needed

			srcChain := chains[path.Src.ChainID]
			dstChain := chains[path.Dst.ChainID]

			srcFromHeight, err := getClientStateLatestHeight(dstChain)
			if err != nil {
				return fmt.Errorf("failed to get client state latest height for src chain: %w", err)
			}

			dstFromHeight, err := getClientStateLatestHeight(srcChain)
			if err != nil {
				return fmt.Errorf("failed to get client state latest height for dst chain: %w", err)
			}

			srcRecord, err := SHFUExecuteAndStore(cmd.Context(), srcChain, dstChain.ChainID(), *srcFromHeight, storage)
			if err != nil {
				return fmt.Errorf("failed to execute and store SHFU for source chain: %w", err)
			}

			dstRecord, err := SHFUExecuteAndStore(cmd.Context(), dstChain, srcChain.ChainID(), *dstFromHeight, storage)
			if err != nil {
				return fmt.Errorf("failed to execute and store SHFU for destination chain: %w", err)
			}

			fmt.Printf("Successfully executed SHFU for both chains:\n")

			// Print detailed summary for source chain
			if srcRecord == nil {
				fmt.Printf("No new SHFU record created for %s->%s\n", srcChain.ChainID(), dstChain.ChainID())
			} else {
				PrintSHFURecordSummary(srcRecord)
			}

			// Print detailed summary for destination chain
			if dstRecord == nil {
				fmt.Printf("No new SHFU record created for %s->%s\n", dstChain.ChainID(), srcChain.ChainID())
			} else {
				PrintSHFURecordSummary(dstRecord)
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
		Use:   "query-chain [path-name] [chain-id]",
		Short: "Query chain information including latest consensus state",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			chains, _, _, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			target := chains[args[1]]

			pathName := args[0]
			targetChainID := args[1]

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

			// Create client.Context using cosmos-sdk's GetClientQueryContext
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return fmt.Errorf("failed to get client query context: %w", err)
			}

			// Query chain information with path and channel information
			opts := SHFUQueryChainOptions{
				PathName:  pathName,
				ChannelID: channelID,
			}

			return SHFUQueryChain(cmd.Context(), target, clientCtx, opts)
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
	cmd.Flags().String(flagGRPCAddr, "", "gRPC server address")
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

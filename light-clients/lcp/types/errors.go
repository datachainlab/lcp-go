package types

import (
	errorsmod "cosmossdk.io/errors"
)

var (
	ErrInvalidStateCommitment      = errorsmod.Register(ModuleName, 1, "invalid state commitment")
	ErrInvalidStateCommitmentProof = errorsmod.Register(ModuleName, 2, "invalid state commitment proof")
	ErrExpiredEnclaveKey           = errorsmod.Register(ModuleName, 3, "enclave key has expired")
	ErrProcessedTimeNotFound       = errorsmod.Register(ModuleName, 4, "processed time not found")
	ErrProcessedHeightNotFound     = errorsmod.Register(ModuleName, 5, "processed height not found")
	ErrDelayPeriodNotPassed        = errorsmod.Register(ModuleName, 6, "packet-specified delay period has not been reached")
	ErrInvalidMisbehaviour         = errorsmod.Register(ModuleName, 7, "invalid misbehaviour")
)

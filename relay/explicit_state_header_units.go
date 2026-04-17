package relay

import (
	"fmt"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
)

type ExplicitStateHeaderUnit struct {
	Header        *codectypes.Any
	TrustedHeight *clienttypes.Height
	BaseState     *ExplicitStateRef
}

func buildExplicitStateHeaderUnits(anyHeaders []*codectypes.Any) ([]*ExplicitStateHeaderUnit, error) {
	if len(anyHeaders) == 0 {
		return nil, nil
	}
	units := make([]*ExplicitStateHeaderUnit, 0, len(anyHeaders))
	for i, anyHeader := range anyHeaders {
		if anyHeader == nil {
			return nil, fmt.Errorf("explicit-state header[%d] must not be nil", i)
		}
		trustedHeight, err := trustedHeightForExplicitState(anyHeader, nil)
		if err != nil {
			return nil, err
		}
		units = append(units, &ExplicitStateHeaderUnit{
			Header:        anyHeader,
			TrustedHeight: trustedHeight,
		})
	}
	return units, nil
}

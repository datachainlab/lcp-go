package relay

import (
	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/datachainlab/lcp-go/relay/enclave"
	"google.golang.org/grpc"
)

type (
	ELCMsgClient       = elc.MsgClient
	ELCQueryClient     = elc.QueryClient
	EnclaveQueryClient = enclave.QueryClient
)

type LCPServiceClient struct {
	conn *grpc.ClientConn
	ELCMsgClient
	ELCQueryClient
	EnclaveQueryClient
}

func NewLCPServiceClient(conn *grpc.ClientConn) LCPServiceClient {
	return LCPServiceClient{
		conn:               conn,
		ELCMsgClient:       elc.NewMsgClient(conn),
		ELCQueryClient:     elc.NewQueryClient(conn),
		EnclaveQueryClient: enclave.NewQueryClient(conn),
	}
}

// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: lcp/service/enclave/v1/query.proto

package enclave

import (
	context "context"
	fmt "fmt"
	_ "github.com/cosmos/gogoproto/gogoproto"
	grpc1 "github.com/cosmos/gogoproto/grpc"
	proto "github.com/cosmos/gogoproto/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type QueryAvailableEnclaveKeysRequest struct {
	Mrenclave []byte `protobuf:"bytes,1,opt,name=mrenclave,proto3" json:"mrenclave,omitempty"`
}

func (m *QueryAvailableEnclaveKeysRequest) Reset()         { *m = QueryAvailableEnclaveKeysRequest{} }
func (m *QueryAvailableEnclaveKeysRequest) String() string { return proto.CompactTextString(m) }
func (*QueryAvailableEnclaveKeysRequest) ProtoMessage()    {}
func (*QueryAvailableEnclaveKeysRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_17b0894e959bbc62, []int{0}
}
func (m *QueryAvailableEnclaveKeysRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryAvailableEnclaveKeysRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryAvailableEnclaveKeysRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryAvailableEnclaveKeysRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryAvailableEnclaveKeysRequest.Merge(m, src)
}
func (m *QueryAvailableEnclaveKeysRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryAvailableEnclaveKeysRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryAvailableEnclaveKeysRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryAvailableEnclaveKeysRequest proto.InternalMessageInfo

type QueryAvailableEnclaveKeysResponse struct {
	Keys []*EnclaveKeyInfo `protobuf:"bytes,1,rep,name=keys,proto3" json:"keys,omitempty"`
}

func (m *QueryAvailableEnclaveKeysResponse) Reset()         { *m = QueryAvailableEnclaveKeysResponse{} }
func (m *QueryAvailableEnclaveKeysResponse) String() string { return proto.CompactTextString(m) }
func (*QueryAvailableEnclaveKeysResponse) ProtoMessage()    {}
func (*QueryAvailableEnclaveKeysResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_17b0894e959bbc62, []int{1}
}
func (m *QueryAvailableEnclaveKeysResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryAvailableEnclaveKeysResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryAvailableEnclaveKeysResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryAvailableEnclaveKeysResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryAvailableEnclaveKeysResponse.Merge(m, src)
}
func (m *QueryAvailableEnclaveKeysResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryAvailableEnclaveKeysResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryAvailableEnclaveKeysResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryAvailableEnclaveKeysResponse proto.InternalMessageInfo

type EnclaveKeyInfo struct {
	EnclaveKeyAddress []byte `protobuf:"bytes,1,opt,name=enclave_key_address,json=enclaveKeyAddress,proto3" json:"enclave_key_address,omitempty"`
	AttestationTime   uint64 `protobuf:"varint,2,opt,name=attestation_time,json=attestationTime,proto3" json:"attestation_time,omitempty"`
	Report            string `protobuf:"bytes,3,opt,name=report,proto3" json:"report,omitempty"`
	Signature         []byte `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	SigningCert       []byte `protobuf:"bytes,5,opt,name=signing_cert,json=signingCert,proto3" json:"signing_cert,omitempty"`
	Extension         []byte `protobuf:"bytes,6,opt,name=extension,proto3" json:"extension,omitempty"`
}

func (m *EnclaveKeyInfo) Reset()         { *m = EnclaveKeyInfo{} }
func (m *EnclaveKeyInfo) String() string { return proto.CompactTextString(m) }
func (*EnclaveKeyInfo) ProtoMessage()    {}
func (*EnclaveKeyInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_17b0894e959bbc62, []int{2}
}
func (m *EnclaveKeyInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *EnclaveKeyInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_EnclaveKeyInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *EnclaveKeyInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EnclaveKeyInfo.Merge(m, src)
}
func (m *EnclaveKeyInfo) XXX_Size() int {
	return m.Size()
}
func (m *EnclaveKeyInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_EnclaveKeyInfo.DiscardUnknown(m)
}

var xxx_messageInfo_EnclaveKeyInfo proto.InternalMessageInfo

type QueryEnclaveKeyRequest struct {
	EnclaveKeyAddress []byte `protobuf:"bytes,1,opt,name=enclave_key_address,json=enclaveKeyAddress,proto3" json:"enclave_key_address,omitempty"`
}

func (m *QueryEnclaveKeyRequest) Reset()         { *m = QueryEnclaveKeyRequest{} }
func (m *QueryEnclaveKeyRequest) String() string { return proto.CompactTextString(m) }
func (*QueryEnclaveKeyRequest) ProtoMessage()    {}
func (*QueryEnclaveKeyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_17b0894e959bbc62, []int{3}
}
func (m *QueryEnclaveKeyRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryEnclaveKeyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryEnclaveKeyRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryEnclaveKeyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryEnclaveKeyRequest.Merge(m, src)
}
func (m *QueryEnclaveKeyRequest) XXX_Size() int {
	return m.Size()
}
func (m *QueryEnclaveKeyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryEnclaveKeyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_QueryEnclaveKeyRequest proto.InternalMessageInfo

type QueryEnclaveKeyResponse struct {
	Key *EnclaveKeyInfo `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
}

func (m *QueryEnclaveKeyResponse) Reset()         { *m = QueryEnclaveKeyResponse{} }
func (m *QueryEnclaveKeyResponse) String() string { return proto.CompactTextString(m) }
func (*QueryEnclaveKeyResponse) ProtoMessage()    {}
func (*QueryEnclaveKeyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_17b0894e959bbc62, []int{4}
}
func (m *QueryEnclaveKeyResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *QueryEnclaveKeyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_QueryEnclaveKeyResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *QueryEnclaveKeyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_QueryEnclaveKeyResponse.Merge(m, src)
}
func (m *QueryEnclaveKeyResponse) XXX_Size() int {
	return m.Size()
}
func (m *QueryEnclaveKeyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_QueryEnclaveKeyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_QueryEnclaveKeyResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*QueryAvailableEnclaveKeysRequest)(nil), "lcp.service.enclave.v1.QueryAvailableEnclaveKeysRequest")
	proto.RegisterType((*QueryAvailableEnclaveKeysResponse)(nil), "lcp.service.enclave.v1.QueryAvailableEnclaveKeysResponse")
	proto.RegisterType((*EnclaveKeyInfo)(nil), "lcp.service.enclave.v1.EnclaveKeyInfo")
	proto.RegisterType((*QueryEnclaveKeyRequest)(nil), "lcp.service.enclave.v1.QueryEnclaveKeyRequest")
	proto.RegisterType((*QueryEnclaveKeyResponse)(nil), "lcp.service.enclave.v1.QueryEnclaveKeyResponse")
}

func init() {
	proto.RegisterFile("lcp/service/enclave/v1/query.proto", fileDescriptor_17b0894e959bbc62)
}

var fileDescriptor_17b0894e959bbc62 = []byte{
	// 457 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x53, 0xcf, 0x6f, 0xd3, 0x30,
	0x14, 0xae, 0xd7, 0xae, 0xd2, 0xbc, 0x89, 0x1f, 0x66, 0x2a, 0x51, 0x85, 0xa2, 0x2c, 0x07, 0x54,
	0x24, 0xb0, 0xb5, 0x71, 0x19, 0x9c, 0x18, 0x08, 0x89, 0x1f, 0x27, 0x02, 0x27, 0x2e, 0x91, 0x9b,
	0x3e, 0x32, 0xab, 0x89, 0x9d, 0xd9, 0x6e, 0x44, 0xee, 0xdc, 0xb8, 0xf0, 0x67, 0xed, 0xb8, 0x23,
	0x47, 0x68, 0xff, 0x11, 0x94, 0xc4, 0x6b, 0x41, 0x1b, 0xa3, 0xec, 0x16, 0x7f, 0xfe, 0xbe, 0x2f,
	0xef, 0x7d, 0xcf, 0x0f, 0x87, 0x59, 0x52, 0x30, 0x03, 0xba, 0x14, 0x09, 0x30, 0x90, 0x49, 0xc6,
	0x4b, 0x60, 0xe5, 0x3e, 0x3b, 0x99, 0x81, 0xae, 0x68, 0xa1, 0x95, 0x55, 0x64, 0x90, 0x25, 0x05,
	0x75, 0x1c, 0xea, 0x38, 0xb4, 0xdc, 0x1f, 0xee, 0xa6, 0x2a, 0x55, 0x0d, 0x85, 0xd5, 0x5f, 0x2d,
	0x3b, 0x7c, 0x86, 0x83, 0x77, 0xb5, 0xf8, 0xa8, 0xe4, 0x22, 0xe3, 0xe3, 0x0c, 0x5e, 0xb6, 0x8a,
	0xb7, 0x50, 0x99, 0x08, 0x4e, 0x66, 0x60, 0x2c, 0xb9, 0x87, 0xb7, 0x72, 0xed, 0x9c, 0x3c, 0x14,
	0xa0, 0xd1, 0x4e, 0xb4, 0x02, 0xc2, 0x18, 0xef, 0x5d, 0xe1, 0x60, 0x0a, 0x25, 0x0d, 0x90, 0xa7,
	0xb8, 0x37, 0x85, 0xca, 0x78, 0x28, 0xe8, 0x8e, 0xb6, 0x0f, 0xee, 0xd3, 0xcb, 0x6b, 0xa4, 0x2b,
	0xe9, 0x6b, 0xf9, 0x49, 0x45, 0x8d, 0x26, 0x9c, 0x23, 0x7c, 0xe3, 0xcf, 0x0b, 0x42, 0xf1, 0x1d,
	0xa7, 0x8a, 0xa7, 0x50, 0xc5, 0x7c, 0x32, 0xd1, 0x60, 0x8c, 0xab, 0xed, 0x36, 0x2c, 0xc9, 0x47,
	0xed, 0x05, 0x79, 0x80, 0x6f, 0x71, 0x6b, 0xc1, 0x58, 0x6e, 0x85, 0x92, 0xb1, 0x15, 0x39, 0x78,
	0x1b, 0x01, 0x1a, 0xf5, 0xa2, 0x9b, 0xbf, 0xe1, 0x1f, 0x44, 0x0e, 0x64, 0x80, 0xfb, 0x1a, 0x0a,
	0xa5, 0xad, 0xd7, 0x0d, 0xd0, 0x68, 0x2b, 0x72, 0xa7, 0x3a, 0x04, 0x23, 0x52, 0xc9, 0xed, 0x4c,
	0x83, 0xd7, 0x6b, 0x43, 0x58, 0x02, 0x64, 0x0f, 0xef, 0xd4, 0x07, 0x21, 0xd3, 0x38, 0x01, 0x6d,
	0xbd, 0xcd, 0x86, 0xb0, 0xed, 0xb0, 0x17, 0xd0, 0x1a, 0xc0, 0x67, 0x0b, 0xd2, 0x08, 0x25, 0xbd,
	0x7e, 0x6b, 0xb0, 0x04, 0xc2, 0x57, 0x78, 0xd0, 0xa4, 0xb8, 0x6a, 0xf4, 0x3c, 0xfd, 0xff, 0xec,
	0x35, 0x7c, 0x8f, 0xef, 0x5e, 0x70, 0x72, 0x53, 0x38, 0xc4, 0xdd, 0x29, 0x54, 0x8d, 0x74, 0xfd,
	0x21, 0xd4, 0x92, 0x83, 0x2f, 0x1b, 0x78, 0xb3, 0x71, 0x25, 0x5f, 0x11, 0xde, 0xbd, 0x6c, 0xd4,
	0xe4, 0xf0, 0x6f, 0x7e, 0xff, 0x7a, 0x5f, 0xc3, 0x27, 0xd7, 0x50, 0xba, 0x8e, 0x72, 0x8c, 0x57,
	0x30, 0xa1, 0x57, 0x1a, 0x5d, 0x88, 0x76, 0xc8, 0xd6, 0xe6, 0xb7, 0xbf, 0x7b, 0xfe, 0xe6, 0xf4,
	0xa7, 0xdf, 0x39, 0x9d, 0xfb, 0xe8, 0x6c, 0xee, 0xa3, 0x1f, 0x73, 0x1f, 0x7d, 0x5b, 0xf8, 0x9d,
	0xb3, 0x85, 0xdf, 0xf9, 0xbe, 0xf0, 0x3b, 0x1f, 0x1f, 0xa6, 0xc2, 0x1e, 0xcf, 0xc6, 0x34, 0x51,
	0x39, 0x9b, 0x70, 0xcb, 0x93, 0x63, 0x2e, 0x64, 0xc6, 0xc7, 0x2c, 0x4b, 0x8a, 0x47, 0xa9, 0x62,
	0x1a, 0x32, 0x5e, 0x9d, 0xaf, 0xed, 0xb8, 0xdf, 0x2c, 0xe0, 0xe3, 0x5f, 0x01, 0x00, 0x00, 0xff,
	0xff, 0xd9, 0x19, 0x22, 0xaa, 0xd4, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// QueryClient is the client API for Query service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type QueryClient interface {
	AvailableEnclaveKeys(ctx context.Context, in *QueryAvailableEnclaveKeysRequest, opts ...grpc.CallOption) (*QueryAvailableEnclaveKeysResponse, error)
	EnclaveKey(ctx context.Context, in *QueryEnclaveKeyRequest, opts ...grpc.CallOption) (*QueryEnclaveKeyResponse, error)
}

type queryClient struct {
	cc grpc1.ClientConn
}

func NewQueryClient(cc grpc1.ClientConn) QueryClient {
	return &queryClient{cc}
}

func (c *queryClient) AvailableEnclaveKeys(ctx context.Context, in *QueryAvailableEnclaveKeysRequest, opts ...grpc.CallOption) (*QueryAvailableEnclaveKeysResponse, error) {
	out := new(QueryAvailableEnclaveKeysResponse)
	err := c.cc.Invoke(ctx, "/lcp.service.enclave.v1.Query/AvailableEnclaveKeys", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *queryClient) EnclaveKey(ctx context.Context, in *QueryEnclaveKeyRequest, opts ...grpc.CallOption) (*QueryEnclaveKeyResponse, error) {
	out := new(QueryEnclaveKeyResponse)
	err := c.cc.Invoke(ctx, "/lcp.service.enclave.v1.Query/EnclaveKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// QueryServer is the server API for Query service.
type QueryServer interface {
	AvailableEnclaveKeys(context.Context, *QueryAvailableEnclaveKeysRequest) (*QueryAvailableEnclaveKeysResponse, error)
	EnclaveKey(context.Context, *QueryEnclaveKeyRequest) (*QueryEnclaveKeyResponse, error)
}

// UnimplementedQueryServer can be embedded to have forward compatible implementations.
type UnimplementedQueryServer struct {
}

func (*UnimplementedQueryServer) AvailableEnclaveKeys(ctx context.Context, req *QueryAvailableEnclaveKeysRequest) (*QueryAvailableEnclaveKeysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AvailableEnclaveKeys not implemented")
}
func (*UnimplementedQueryServer) EnclaveKey(ctx context.Context, req *QueryEnclaveKeyRequest) (*QueryEnclaveKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnclaveKey not implemented")
}

func RegisterQueryServer(s grpc1.Server, srv QueryServer) {
	s.RegisterService(&_Query_serviceDesc, srv)
}

func _Query_AvailableEnclaveKeys_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryAvailableEnclaveKeysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).AvailableEnclaveKeys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lcp.service.enclave.v1.Query/AvailableEnclaveKeys",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).AvailableEnclaveKeys(ctx, req.(*QueryAvailableEnclaveKeysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Query_EnclaveKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QueryEnclaveKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(QueryServer).EnclaveKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lcp.service.enclave.v1.Query/EnclaveKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(QueryServer).EnclaveKey(ctx, req.(*QueryEnclaveKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "lcp.service.enclave.v1.Query",
	HandlerType: (*QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AvailableEnclaveKeys",
			Handler:    _Query_AvailableEnclaveKeys_Handler,
		},
		{
			MethodName: "EnclaveKey",
			Handler:    _Query_EnclaveKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "lcp/service/enclave/v1/query.proto",
}

func (m *QueryAvailableEnclaveKeysRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryAvailableEnclaveKeysRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryAvailableEnclaveKeysRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Mrenclave) > 0 {
		i -= len(m.Mrenclave)
		copy(dAtA[i:], m.Mrenclave)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Mrenclave)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryAvailableEnclaveKeysResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryAvailableEnclaveKeysResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryAvailableEnclaveKeysResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Keys) > 0 {
		for iNdEx := len(m.Keys) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Keys[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintQuery(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *EnclaveKeyInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *EnclaveKeyInfo) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *EnclaveKeyInfo) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Extension) > 0 {
		i -= len(m.Extension)
		copy(dAtA[i:], m.Extension)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Extension)))
		i--
		dAtA[i] = 0x32
	}
	if len(m.SigningCert) > 0 {
		i -= len(m.SigningCert)
		copy(dAtA[i:], m.SigningCert)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.SigningCert)))
		i--
		dAtA[i] = 0x2a
	}
	if len(m.Signature) > 0 {
		i -= len(m.Signature)
		copy(dAtA[i:], m.Signature)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Signature)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.Report) > 0 {
		i -= len(m.Report)
		copy(dAtA[i:], m.Report)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.Report)))
		i--
		dAtA[i] = 0x1a
	}
	if m.AttestationTime != 0 {
		i = encodeVarintQuery(dAtA, i, uint64(m.AttestationTime))
		i--
		dAtA[i] = 0x10
	}
	if len(m.EnclaveKeyAddress) > 0 {
		i -= len(m.EnclaveKeyAddress)
		copy(dAtA[i:], m.EnclaveKeyAddress)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.EnclaveKeyAddress)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryEnclaveKeyRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryEnclaveKeyRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryEnclaveKeyRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.EnclaveKeyAddress) > 0 {
		i -= len(m.EnclaveKeyAddress)
		copy(dAtA[i:], m.EnclaveKeyAddress)
		i = encodeVarintQuery(dAtA, i, uint64(len(m.EnclaveKeyAddress)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *QueryEnclaveKeyResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *QueryEnclaveKeyResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *QueryEnclaveKeyResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Key != nil {
		{
			size, err := m.Key.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintQuery(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintQuery(dAtA []byte, offset int, v uint64) int {
	offset -= sovQuery(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *QueryAvailableEnclaveKeysRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Mrenclave)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryAvailableEnclaveKeysResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Keys) > 0 {
		for _, e := range m.Keys {
			l = e.Size()
			n += 1 + l + sovQuery(uint64(l))
		}
	}
	return n
}

func (m *EnclaveKeyInfo) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.EnclaveKeyAddress)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	if m.AttestationTime != 0 {
		n += 1 + sovQuery(uint64(m.AttestationTime))
	}
	l = len(m.Report)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	l = len(m.Signature)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	l = len(m.SigningCert)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	l = len(m.Extension)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryEnclaveKeyRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.EnclaveKeyAddress)
	if l > 0 {
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func (m *QueryEnclaveKeyResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Key != nil {
		l = m.Key.Size()
		n += 1 + l + sovQuery(uint64(l))
	}
	return n
}

func sovQuery(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozQuery(x uint64) (n int) {
	return sovQuery(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *QueryAvailableEnclaveKeysRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryAvailableEnclaveKeysRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryAvailableEnclaveKeysRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Mrenclave", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Mrenclave = append(m.Mrenclave[:0], dAtA[iNdEx:postIndex]...)
			if m.Mrenclave == nil {
				m.Mrenclave = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryAvailableEnclaveKeysResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryAvailableEnclaveKeysResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryAvailableEnclaveKeysResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Keys", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Keys = append(m.Keys, &EnclaveKeyInfo{})
			if err := m.Keys[len(m.Keys)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *EnclaveKeyInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: EnclaveKeyInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: EnclaveKeyInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EnclaveKeyAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.EnclaveKeyAddress = append(m.EnclaveKeyAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.EnclaveKeyAddress == nil {
				m.EnclaveKeyAddress = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AttestationTime", wireType)
			}
			m.AttestationTime = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AttestationTime |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Report", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Report = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Signature", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Signature = append(m.Signature[:0], dAtA[iNdEx:postIndex]...)
			if m.Signature == nil {
				m.Signature = []byte{}
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SigningCert", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SigningCert = append(m.SigningCert[:0], dAtA[iNdEx:postIndex]...)
			if m.SigningCert == nil {
				m.SigningCert = []byte{}
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Extension", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Extension = append(m.Extension[:0], dAtA[iNdEx:postIndex]...)
			if m.Extension == nil {
				m.Extension = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryEnclaveKeyRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryEnclaveKeyRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryEnclaveKeyRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EnclaveKeyAddress", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.EnclaveKeyAddress = append(m.EnclaveKeyAddress[:0], dAtA[iNdEx:postIndex]...)
			if m.EnclaveKeyAddress == nil {
				m.EnclaveKeyAddress = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *QueryEnclaveKeyResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: QueryEnclaveKeyResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: QueryEnclaveKeyResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthQuery
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthQuery
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Key == nil {
				m.Key = &EnclaveKeyInfo{}
			}
			if err := m.Key.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipQuery(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthQuery
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipQuery(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowQuery
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowQuery
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthQuery
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupQuery
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthQuery
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthQuery        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowQuery          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupQuery = fmt.Errorf("proto: unexpected end of group")
)

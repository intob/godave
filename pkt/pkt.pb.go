// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.1
// source: pkt.proto

package pkt

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Op int32

const (
	Op_SET Op = 0 // SET value of key
	Op_GET Op = 1 // GET value of key
	Op_VAL Op = 2 // response to GET
)

// Enum value maps for Op.
var (
	Op_name = map[int32]string{
		0: "SET",
		1: "GET",
		2: "VAL",
	}
	Op_value = map[string]int32{
		"SET": 0,
		"GET": 1,
		"VAL": 2,
	}
)

func (x Op) Enum() *Op {
	p := new(Op)
	*p = x
	return p
}

func (x Op) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Op) Descriptor() protoreflect.EnumDescriptor {
	return file_pkt_proto_enumTypes[0].Descriptor()
}

func (Op) Type() protoreflect.EnumType {
	return &file_pkt_proto_enumTypes[0]
}

func (x Op) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Op.Descriptor instead.
func (Op) EnumDescriptor() ([]byte, []int) {
	return file_pkt_proto_rawDescGZIP(), []int{0}
}

type Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Op    Op       `protobuf:"varint,1,opt,name=op,proto3,enum=Op" json:"op,omitempty"`
	Route []string `protobuf:"bytes,3,rep,name=route,proto3" json:"route,omitempty"` // set of addr:port
	Key   string   `protobuf:"bytes,4,opt,name=key,proto3" json:"key,omitempty"`
	Val   []byte   `protobuf:"bytes,5,opt,name=val,proto3" json:"val,omitempty"`
}

func (x *Msg) Reset() {
	*x = Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkt_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Msg) ProtoMessage() {}

func (x *Msg) ProtoReflect() protoreflect.Message {
	mi := &file_pkt_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Msg.ProtoReflect.Descriptor instead.
func (*Msg) Descriptor() ([]byte, []int) {
	return file_pkt_proto_rawDescGZIP(), []int{0}
}

func (x *Msg) GetOp() Op {
	if x != nil {
		return x.Op
	}
	return Op_SET
}

func (x *Msg) GetRoute() []string {
	if x != nil {
		return x.Route
	}
	return nil
}

func (x *Msg) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (x *Msg) GetVal() []byte {
	if x != nil {
		return x.Val
	}
	return nil
}

var File_pkt_proto protoreflect.FileDescriptor

var file_pkt_proto_rawDesc = []byte{
	0x0a, 0x09, 0x70, 0x6b, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x54, 0x0a, 0x03, 0x4d,
	0x73, 0x67, 0x12, 0x13, 0x0a, 0x02, 0x6f, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x03,
	0x2e, 0x4f, 0x70, 0x52, 0x02, 0x6f, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x10, 0x0a,
	0x03, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x76, 0x61, 0x6c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x76, 0x61,
	0x6c, 0x2a, 0x1f, 0x0a, 0x02, 0x4f, 0x70, 0x12, 0x07, 0x0a, 0x03, 0x53, 0x45, 0x54, 0x10, 0x00,
	0x12, 0x07, 0x0a, 0x03, 0x47, 0x45, 0x54, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x56, 0x41, 0x4c,
	0x10, 0x02, 0x42, 0x07, 0x5a, 0x05, 0x2e, 0x2f, 0x70, 0x6b, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_pkt_proto_rawDescOnce sync.Once
	file_pkt_proto_rawDescData = file_pkt_proto_rawDesc
)

func file_pkt_proto_rawDescGZIP() []byte {
	file_pkt_proto_rawDescOnce.Do(func() {
		file_pkt_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkt_proto_rawDescData)
	})
	return file_pkt_proto_rawDescData
}

var file_pkt_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pkt_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pkt_proto_goTypes = []interface{}{
	(Op)(0),     // 0: Op
	(*Msg)(nil), // 1: Msg
}
var file_pkt_proto_depIdxs = []int32{
	0, // 0: Msg.op:type_name -> Op
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pkt_proto_init() }
func file_pkt_proto_init() {
	if File_pkt_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkt_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Msg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkt_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pkt_proto_goTypes,
		DependencyIndexes: file_pkt_proto_depIdxs,
		EnumInfos:         file_pkt_proto_enumTypes,
		MessageInfos:      file_pkt_proto_msgTypes,
	}.Build()
	File_pkt_proto = out.File
	file_pkt_proto_rawDesc = nil
	file_pkt_proto_goTypes = nil
	file_pkt_proto_depIdxs = nil
}

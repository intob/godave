// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.1
// source: dave.proto

package davepb

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
	Op_SETDAT  Op = 0
	Op_GETDAT  Op = 1
	Op_DAT     Op = 2
	Op_GETADDR Op = 3
	Op_ADDR    Op = 4
)

// Enum value maps for Op.
var (
	Op_name = map[int32]string{
		0: "SETDAT",
		1: "GETDAT",
		2: "DAT",
		3: "GETADDR",
		4: "ADDR",
	}
	Op_value = map[string]int32{
		"SETDAT":  0,
		"GETDAT":  1,
		"DAT":     2,
		"GETADDR": 3,
		"ADDR":    4,
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
	return file_dave_proto_enumTypes[0].Descriptor()
}

func (Op) Type() protoreflect.EnumType {
	return &file_dave_proto_enumTypes[0]
}

func (x Op) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Op.Descriptor instead.
func (Op) EnumDescriptor() ([]byte, []int) {
	return file_dave_proto_rawDescGZIP(), []int{0}
}

type Msg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Op    Op       `protobuf:"varint,1,opt,name=op,proto3,enum=Op" json:"op,omitempty"` // operation
	Addrs []string `protobuf:"bytes,2,rep,name=addrs,proto3" json:"addrs,omitempty"`    // set of addr:port
	Val   []byte   `protobuf:"bytes,3,opt,name=val,proto3" json:"val,omitempty"`        // anything
	Time  []byte   `protobuf:"bytes,4,opt,name=time,proto3" json:"time,omitempty"`      // 15B? big-endian unix milli
	Nonce []byte   `protobuf:"bytes,5,opt,name=nonce,proto3" json:"nonce,omitempty"`    // 32B random
	Work  []byte   `protobuf:"bytes,6,opt,name=work,proto3" json:"work,omitempty"`      // 32B sha256
	Prev  []byte   `protobuf:"bytes,7,opt,name=prev,proto3" json:"prev,omitempty"`      // 32B sha256
}

func (x *Msg) Reset() {
	*x = Msg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_dave_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Msg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Msg) ProtoMessage() {}

func (x *Msg) ProtoReflect() protoreflect.Message {
	mi := &file_dave_proto_msgTypes[0]
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
	return file_dave_proto_rawDescGZIP(), []int{0}
}

func (x *Msg) GetOp() Op {
	if x != nil {
		return x.Op
	}
	return Op_SETDAT
}

func (x *Msg) GetAddrs() []string {
	if x != nil {
		return x.Addrs
	}
	return nil
}

func (x *Msg) GetVal() []byte {
	if x != nil {
		return x.Val
	}
	return nil
}

func (x *Msg) GetTime() []byte {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *Msg) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *Msg) GetWork() []byte {
	if x != nil {
		return x.Work
	}
	return nil
}

func (x *Msg) GetPrev() []byte {
	if x != nil {
		return x.Prev
	}
	return nil
}

var File_dave_proto protoreflect.FileDescriptor

var file_dave_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x64, 0x61, 0x76, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x94, 0x01, 0x0a,
	0x03, 0x4d, 0x73, 0x67, 0x12, 0x13, 0x0a, 0x02, 0x6f, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x03, 0x2e, 0x4f, 0x70, 0x52, 0x02, 0x6f, 0x70, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x64, 0x64,
	0x72, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x61, 0x64, 0x64, 0x72, 0x73, 0x12,
	0x10, 0x0a, 0x03, 0x76, 0x61, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x76, 0x61,
	0x6c, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x77,
	0x6f, 0x72, 0x6b, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x77, 0x6f, 0x72, 0x6b, 0x12,
	0x12, 0x0a, 0x04, 0x70, 0x72, 0x65, 0x76, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x70,
	0x72, 0x65, 0x76, 0x2a, 0x3c, 0x0a, 0x02, 0x4f, 0x70, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x45, 0x54,
	0x44, 0x41, 0x54, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x47, 0x45, 0x54, 0x44, 0x41, 0x54, 0x10,
	0x01, 0x12, 0x07, 0x0a, 0x03, 0x44, 0x41, 0x54, 0x10, 0x02, 0x12, 0x0b, 0x0a, 0x07, 0x47, 0x45,
	0x54, 0x41, 0x44, 0x44, 0x52, 0x10, 0x03, 0x12, 0x08, 0x0a, 0x04, 0x41, 0x44, 0x44, 0x52, 0x10,
	0x04, 0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x2f, 0x64, 0x61, 0x76, 0x65, 0x70, 0x62, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_dave_proto_rawDescOnce sync.Once
	file_dave_proto_rawDescData = file_dave_proto_rawDesc
)

func file_dave_proto_rawDescGZIP() []byte {
	file_dave_proto_rawDescOnce.Do(func() {
		file_dave_proto_rawDescData = protoimpl.X.CompressGZIP(file_dave_proto_rawDescData)
	})
	return file_dave_proto_rawDescData
}

var file_dave_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_dave_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_dave_proto_goTypes = []interface{}{
	(Op)(0),     // 0: Op
	(*Msg)(nil), // 1: Msg
}
var file_dave_proto_depIdxs = []int32{
	0, // 0: Msg.op:type_name -> Op
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_dave_proto_init() }
func file_dave_proto_init() {
	if File_dave_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_dave_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
			RawDescriptor: file_dave_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_dave_proto_goTypes,
		DependencyIndexes: file_dave_proto_depIdxs,
		EnumInfos:         file_dave_proto_enumTypes,
		MessageInfos:      file_dave_proto_msgTypes,
	}.Build()
	File_dave_proto = out.File
	file_dave_proto_rawDesc = nil
	file_dave_proto_goTypes = nil
	file_dave_proto_depIdxs = nil
}

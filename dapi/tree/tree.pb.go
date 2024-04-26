// Copyright 2024 Joey Innes <joey@inneslabs.uk>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.1
// source: tree.proto

package tree

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

type Tree struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Trees []*Tree `protobuf:"bytes,1,rep,name=trees,proto3" json:"trees,omitempty"`
	Work  []byte  `protobuf:"bytes,2,opt,name=work,proto3" json:"work,omitempty"`
}

func (x *Tree) Reset() {
	*x = Tree{}
	if protoimpl.UnsafeEnabled {
		mi := &file_tree_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tree) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tree) ProtoMessage() {}

func (x *Tree) ProtoReflect() protoreflect.Message {
	mi := &file_tree_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tree.ProtoReflect.Descriptor instead.
func (*Tree) Descriptor() ([]byte, []int) {
	return file_tree_proto_rawDescGZIP(), []int{0}
}

func (x *Tree) GetTrees() []*Tree {
	if x != nil {
		return x.Trees
	}
	return nil
}

func (x *Tree) GetWork() []byte {
	if x != nil {
		return x.Work
	}
	return nil
}

var File_tree_proto protoreflect.FileDescriptor

var file_tree_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x74, 0x72, 0x65, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x37, 0x0a, 0x04,
	0x54, 0x72, 0x65, 0x65, 0x12, 0x1b, 0x0a, 0x05, 0x74, 0x72, 0x65, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x05, 0x2e, 0x54, 0x72, 0x65, 0x65, 0x52, 0x05, 0x74, 0x72, 0x65, 0x65,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x04, 0x77, 0x6f, 0x72, 0x6b, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2f, 0x74, 0x72, 0x65, 0x65, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_tree_proto_rawDescOnce sync.Once
	file_tree_proto_rawDescData = file_tree_proto_rawDesc
)

func file_tree_proto_rawDescGZIP() []byte {
	file_tree_proto_rawDescOnce.Do(func() {
		file_tree_proto_rawDescData = protoimpl.X.CompressGZIP(file_tree_proto_rawDescData)
	})
	return file_tree_proto_rawDescData
}

var file_tree_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_tree_proto_goTypes = []interface{}{
	(*Tree)(nil), // 0: Tree
}
var file_tree_proto_depIdxs = []int32{
	0, // 0: Tree.trees:type_name -> Tree
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_tree_proto_init() }
func file_tree_proto_init() {
	if File_tree_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_tree_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tree); i {
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
			RawDescriptor: file_tree_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_tree_proto_goTypes,
		DependencyIndexes: file_tree_proto_depIdxs,
		MessageInfos:      file_tree_proto_msgTypes,
	}.Build()
	File_tree_proto = out.File
	file_tree_proto_rawDesc = nil
	file_tree_proto_goTypes = nil
	file_tree_proto_depIdxs = nil
}

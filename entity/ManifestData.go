package entity

import "container/list"

type HEADER struct {
	ResType    uint16
	HeaderSize uint16
	Filesize   uint32
}

type StringChunk struct {
	ScType             uint16
	HeaderSize         uint16
	ScSize             uint32
	ScStringCount      uint32
	ScStyleCount       uint32
	Flags              uint32
	ScStringPoolOffset uint32
	ScStylePoolOffset  uint32
}

type ONECHAR struct {
	C1 uint8
	C2 uint8
}

type STRING_ITEM struct {
	SfSize  uint16
	Content []ONECHAR
	SfEnd   uint16
}

type RESOURCEIDCHUNK struct {
	ResType    uint16
	HeaderSize uint16
	RcSize     uint32
	ResItems   []uint32
}

// Define the Start Namespace Chunk
type SNCHUNK struct {
	ResType       uint16
	HeaderSize    uint16
	SncSize       uint32
	SncLineNumber uint32
	SncComment    uint32
	SncPrefix     uint32
	SncUri        uint32
}

// Define the End Namespace Chunk
type ENCHUNK struct {
	ResType       uint16
	HeaderSize    uint16
	EncSize       uint32
	EncLineNumber uint32
	SncComment    uint32
	EncPrefix     uint32
	EncUri        uint32
}

// Define the Attribute Chunk
type ATTRIBUTECHUNK struct {
	AcNamespaceUri uint32
	AcName         uint32
	AcValueStr     uint32
	ResValueSize   uint16
	Res0           uint8
	ResDataType    uint8
	AcData         uint32
}

// Define the Start Tag Chunk
type STCHUNK struct {
	ResType           uint16
	HeaderSize        uint16
	StcSize           uint32
	StcLineNumber     uint32
	StcComment        uint32
	StcNamespaceUri   uint32
	StcName           uint32
	StcFlags          uint32
	StcAttributeCount uint32
	StcClassAttribute uint32
	AttributeChunk    []ATTRIBUTECHUNK
}

// Define the End Tag Chunk
type ETCHUNK struct {
	ResType         uint16
	HeaderSize      uint16
	EtcSize         uint32
	EtcLineNumber   uint32
	EtcComment      uint32
	EtcNamespaceUri uint32
	EtcName         uint32
}

// Define the Text Chunk
type TEXTCHUNK struct {
	ResType      uint16
	HeaderSize   uint16
	TcSize       uint32
	TcLineNumber uint32
	TcUNKNOWN01  uint32
	TcName       uint32
	TcUNKNOWN02  uint32
	TcUNNNOWN03  uint32
}

const (
	START_NAMESPACE_CHUNK = 0x00100100
	END_NAMESPACE_CHUNK   = 0x00100101
	START_TAG_CHUNK       = 0x00100102
	END_TAG_CHUNK         = 0x00100103
	TEXT_CHUNK            = 0x00100104
)

type ManifestData struct {
	Header          HEADER
	StringChunk     StringChunk
	ScStringOffsets []uint32
	ScStyleOffset   []uint32
	ScItems         []STRING_ITEM
	ResChunk        RESOURCEIDCHUNK
	OtherChunks     *list.List
	PackageName     string
	Application     string
	Activity        map[string]bool
	UsesPermission  *list.List
}

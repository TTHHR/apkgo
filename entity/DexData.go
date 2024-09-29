package entity

const (
	STAND_DEX_MAGIC    = "dex\n" // 直接使用字符串表示
	COMPACT_DEX_MAGIC  = "cdex"  // 直接使用字符串表示
	KDexEndianConstant = 0x12345678
)

var (
	VERSION_035 = []byte{'0', '3', '5', 0}
	VERSION_037 = []byte{'0', '3', '7', 0}
	VERSION_038 = []byte{'0', '3', '8', 0}
	VERSION_039 = []byte{'0', '3', '9', 0}
	VERSION_001 = []byte{'0', '0', '1', 0}
)

type MapItemType uint16

const (
	KDexTypeHeaderItem               MapItemType = 0x0000
	KDexTypeStringIdItem             MapItemType = 0x0001
	KDexTypeTypeIdItem               MapItemType = 0x0002
	KDexTypeProtoIdItem              MapItemType = 0x0003
	KDexTypeFieldIdItem              MapItemType = 0x0004
	KDexTypeMethodIdItem             MapItemType = 0x0005
	KDexTypeClassDefItem             MapItemType = 0x0006
	KDexTypeCallSiteIdItem           MapItemType = 0x0007
	KDexTypeMethodHandleItem         MapItemType = 0x0008
	KDexTypeMapList                  MapItemType = 0x1000
	KDexTypeTypeList                 MapItemType = 0x1001
	KDexTypeAnnotationSetRefList     MapItemType = 0x1002
	KDexTypeAnnotationSetItem        MapItemType = 0x1003
	KDexTypeClassDataItem            MapItemType = 0x2000
	KDexTypeCodeItem                 MapItemType = 0x2001
	KDexTypeStringDataItem           MapItemType = 0x2002
	KDexTypeDebugInfoItem            MapItemType = 0x2003
	KDexTypeAnnotationItem           MapItemType = 0x2004
	KDexTypeEncodedArrayItem         MapItemType = 0x2005
	KDexTypeAnnotationsDirectoryItem MapItemType = 0x2006
	KDexTypeHiddenapiClassData       MapItemType = 0xF000
)

const (
	ACC_PUBLIC       = 0x0001
	ACC_PRIVATE      = 0x0002
	ACC_PROTECTED    = 0x0004
	ACC_STATIC       = 0x0008
	ACC_FINAL        = 0x0010
	ACC_SYNCHRONIZED = 0x0020
	ACC_VOLATILE     = 0x0040
	ACC_TRANSIENT    = 0x0080
	ACC_INTERFACE    = 0x1000
	ACC_ABSTRACT     = 0x2000
)

// MapItem 对应于 C++ 中的结构体
type MapItem struct {
	Type   uint16 // 对应于 type_
	Unused uint16 // 对应于 unused_
	Size   uint32 // 对应于 size_
	Offset uint32 // 对应于 offset_
}

// MapList 对应于 C++ 中的结构体
type MapList struct {
	Size_ uint32    // 对应于 size_
	List_ []MapItem // 对应于 list_[1]，在 Go 中我们用切片表示变长数组
}

type ClassDef struct {
	Class_idx_         uint16 // index into type_ids_ array for this class
	Pad1_              uint16 // padding = 0
	Access_flags_      uint32
	Superclass_idx_    uint16 // index into type_ids_ array for superclass
	Pad2_              uint16 // padding = 0
	Interfaces_off_    uint32 // file offset to TypeList
	Source_file_idx_   uint32 // index into string_ids_ for source file name
	Annotations_off_   uint32 // file offset to annotations_directory_item
	Class_data_off_    uint32 // file offset to ClassDataItem
	Static_values_off_ uint32 // file offset to EncodedArray
	ClassName          string
	SupperClassName    string
	ClassDataItem      ClassDataItem
}

type MethodCodeItem struct {
	RegistersSize uint16   // 使用的寄存器个数
	InsSize       uint16   // 参数个数
	OutsSize      uint16   // 调用其他方法时使用的寄存器个数
	TriesSize     uint16   // Try/Catch 个数
	DebbugInfoOff uint32   // 指向调试信息的偏移
	InsnsSize     uint32   // 指令集个数，以 2 字节为单位
	Insns         []uint16 // 指令集
}

type MethodIdDef struct {
	Class_idx_ uint16 // index into type_ids_ array for defining class
	Proto_idx_ uint16 // index into proto_ids_ array for method prototype
	Name_idx_  uint32 // index into string_ids_ array for method name
	MethodName string
}
type MethodDef struct {
	MethodIdx   uint32 // 指向 DexMethodId 的索引
	AccessFlags uint32 // 访问标志
	CodeOff     uint32 // 指向 DexCode 结构的偏移
}

// ClassDataItem 结构体
type ClassDataItem struct {
	StaticFieldsSize   uint32      // 静态字段个数
	InstanceFieldsSize uint32      // 实例字段个数
	DirectMethodsSize  uint32      // 直接方法个数
	VirtualMethodsSize uint32      // 虚方法个数
	StaticFields       []DexField  //静态方法
	InstanceFields     []DexField  //静态方法
	DirectMethods      []MethodDef //静态方法
	VirtualMethods     []MethodDef //静态方法
}

type DexField struct {
	FieldIdx    uint32 // 指向 DexFieldId 的索引
	AccessFlags uint32 // 访问标志
}

type DexHeader struct {
	Magic         [4]byte  // 文件魔数
	Version       [4]byte  //dex version
	CheckSum      uint32   // 校验和
	Signature     [20]byte // 签名
	FileSize      uint32   // 文件大小
	HeaderSize    uint32   // 头部大小
	EndianTag     uint32   // 大小端标志
	LinkSize      uint32   // 链接大小
	LinkOffset    uint32   // 链接偏移
	MapOff        uint32   // 映射表偏移
	StringIdsSize uint32   // 字符串 ID 数量
	StringIdsOff  uint32   // 字符串 ID 偏移
	TypeIdsSize   uint32   // 类型 ID 数量
	TypeIdsOff    uint32   // 类型 ID 偏移
	ProtoIdsSize  uint32   /* DexProtoId的个数 */
	ProtoIdsOff   uint32   /* DexStringId的偏移 */
	FieldIdsSize  uint32   /* DexFieldId的个数 */
	FieldIdsOff   uint32   /* DexFieldId的偏移 */
	MethodIdsSize uint32   /* DexMethodId的个数 */
	MethodIdsOff  uint32   /* DexMethodId的偏移 */
	ClassDefsSize uint32   /* DexClassDef的个数 */
	ClassDefsOff  uint32   /* DexClassDef的偏移 */
	DataSize      uint32   /* 数据段的大小 */
	DataOff       uint32   /* 数据段的偏移 */
}
type DexFile struct {
	Header    DexHeader
	Oridata   []byte
	FileName  string
	ValidDex  bool
	MapList   *MapList
	StringIds []uint32
	ClassDef  []ClassDef
	Strings   map[uint32]string
	Typeids   []uint32
	MethodIds []MethodIdDef
}

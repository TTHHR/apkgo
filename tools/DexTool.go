package tools

import (
	"apkgo/entity"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
	"os"
	"strings"
)

func LoadDex(filepath string) (*entity.DexFile, error) {
	file, err := os.Open(filepath)
	if err != nil {
		debugPrint("Error opening dex:%s", err)
		return nil, fmt.Errorf("opening can not open")
	}
	defer file.Close()
	data := &entity.DexFile{
		Strings: make(map[uint32]string),
	}

	err = binary.Read(file, binary.LittleEndian, &data.Header)
	if err != nil {
		return nil, err
	}
	debugPrint("filesize %d headersize %d\n", data.Header.FileSize, data.Header.HeaderSize)
	data.Oridata = make([]byte, data.Header.FileSize-data.Header.HeaderSize) // 根据 Size 分配空间
	err = binary.Read(file, binary.LittleEndian, &data.Oridata)
	if err != nil {
		return nil, err
	}
	data.FileName = filepath
	return data, nil
}

func isMagicValid(magic []byte) bool {
	if string(magic) == entity.STAND_DEX_MAGIC {
		return true
	}
	if string(magic) == entity.COMPACT_DEX_MAGIC {
		return true
	}
	return false
}

func isVersionValid(version []byte) bool {

	if bytes.Equal(version, entity.VERSION_001) {
		return true
	}
	if bytes.Equal(version, entity.VERSION_035) {
		return true
	}
	if bytes.Equal(version, entity.VERSION_037) {
		return true
	}
	if bytes.Equal(version, entity.VERSION_038) {
		return true
	}
	if bytes.Equal(version, entity.VERSION_039) {
		return true
	}
	return false
}
func calculateChecksum(d *entity.DexFile) uint32 {
	// 初始化 Adler-32 checksum
	checksum := adler32.New()

	// 写入 Header 的内容（排除 Magic, Version, CheckSum 字段）
	binary.Write(checksum, binary.LittleEndian, d.Header.Signature)
	binary.Write(checksum, binary.LittleEndian, d.Header.FileSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.HeaderSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.EndianTag)
	binary.Write(checksum, binary.LittleEndian, d.Header.LinkSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.LinkOffset)
	binary.Write(checksum, binary.LittleEndian, d.Header.MapOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.StringIdsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.StringIdsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.TypeIdsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.TypeIdsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.ProtoIdsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.ProtoIdsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.FieldIdsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.FieldIdsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.MethodIdsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.MethodIdsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.ClassDefsSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.ClassDefsOff)
	binary.Write(checksum, binary.LittleEndian, d.Header.DataSize)
	binary.Write(checksum, binary.LittleEndian, d.Header.DataOff)

	// 写入 Oridata 数据
	checksum.Write(d.Oridata)

	// 返回计算的 checksum
	return checksum.Sum32()
}
func IsAlignedParam(offset uint32, alignment uint32) bool {
	return offset%uint32(alignment) == 0
}
func checkValidOffsetAndSize(size uint32, fileSize uint32, offset uint32, alignment uint32, label string) bool {

	if size == 0 {
		if offset != 0 {
			debugPrint("Offset(%d) should be zero when size is zero for %s.", offset, label)
			return false
		}
	}
	if fileSize <= offset {
		debugPrint("Offset(%d) should be within file size(%d) for %s.", offset, fileSize, label)
		return false
	}
	if alignment != 0 && !IsAlignedParam(offset, alignment) {
		debugPrint("Offset(%d) should be aligned by %d for %s.", offset, alignment, label)
		return false
	}

	return true
}

func checkHeader(dex *entity.DexFile) bool {

	adler_checksum := calculateChecksum(dex)

	if adler_checksum != dex.Header.CheckSum {
		debugPrint("checksum %x %x\n", adler_checksum, dex.Header.CheckSum)
		return false
	}

	if dex.Header.EndianTag != entity.KDexEndianConstant {
		debugPrint("EndianTag %x %x\n", dex.Header.EndianTag, entity.KDexEndianConstant)
		return false
	}

	offset := dex.Header.LinkOffset
	size := dex.Header.LinkSize
	var alignment uint32 = 0
	label := "link"

	if !checkValidOffsetAndSize(size, dex.Header.FileSize, offset, alignment, label) {
		return false
	}

	offset = dex.Header.MapOff
	size = dex.Header.MapOff
	alignment = 4
	label = "map"

	if !checkValidOffsetAndSize(size, dex.Header.FileSize, offset, alignment, label) {
		return false
	}

	offset = dex.Header.StringIdsOff
	size = dex.Header.StringIdsSize
	alignment = 4
	label = "string-ids"

	if !checkValidOffsetAndSize(size, dex.Header.FileSize, offset, alignment, label) {
		return false
	}

	offset = dex.Header.TypeIdsOff
	size = dex.Header.TypeIdsSize
	alignment = 4
	label = "type-ids"

	if !checkValidOffsetAndSize(size, dex.Header.FileSize, offset, alignment, label) {
		return false
	}
	offset = dex.Header.DataOff
	size = dex.Header.DataSize
	alignment = 0
	label = "data"

	return checkValidOffsetAndSize(size, dex.Header.FileSize, offset, alignment, label)
}
func mapTypeToBitMask(mapItemType entity.MapItemType) uint32 {
	switch mapItemType {
	case entity.KDexTypeHeaderItem:
		return 1 << 0
	case entity.KDexTypeStringIdItem:
		return 1 << 1
	case entity.KDexTypeTypeIdItem:
		return 1 << 2
	case entity.KDexTypeProtoIdItem:
		return 1 << 3
	case entity.KDexTypeFieldIdItem:
		return 1 << 4
	case entity.KDexTypeMethodIdItem:
		return 1 << 5
	case entity.KDexTypeClassDefItem:
		return 1 << 6
	case entity.KDexTypeCallSiteIdItem:
		return 1 << 7
	case entity.KDexTypeMethodHandleItem:
		return 1 << 8
	case entity.KDexTypeMapList:
		return 1 << 9
	case entity.KDexTypeTypeList:
		return 1 << 10
	case entity.KDexTypeAnnotationSetRefList:
		return 1 << 11
	case entity.KDexTypeAnnotationSetItem:
		return 1 << 12
	case entity.KDexTypeClassDataItem:
		return 1 << 13
	case entity.KDexTypeCodeItem:
		return 1 << 14
	case entity.KDexTypeStringDataItem:
		return 1 << 15
	case entity.KDexTypeDebugInfoItem:
		return 1 << 16
	case entity.KDexTypeAnnotationItem:
		return 1 << 17
	case entity.KDexTypeEncodedArrayItem:
		return 1 << 18
	case entity.KDexTypeAnnotationsDirectoryItem:
		return 1 << 19
	case entity.KDexTypeHiddenapiClassData:
		return 1 << 20
	}
	return 0
}

// 从字节切片中读取 MapList 和 MapItems
func byteSliceToMapList(data []byte) (*entity.MapList, error) {

	size := binary.LittleEndian.Uint32(data[0:4])

	// 确保数据长度足够
	if len(data) < int(4+size*12) { // 每个 MapItem 是 8 字节（2 字节 + 2 字节 + 4 字节 + 4 字节）
		return nil, errors.New("data is too small to contain all MapItems")
	}

	// 创建 MapList 实例
	mapList := &entity.MapList{
		Size_: size,
		List_: make([]entity.MapItem, size),
	}

	// 逐个读取 MapItem
	for i := uint32(0); i < size; i++ {
		offset := 4 + int(i)*12 // 每个 MapItem 占 8 字节
		mapItem := entity.MapItem{
			Type:   binary.LittleEndian.Uint16(data[offset : offset+2]),
			Unused: binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
			Size:   binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
			Offset: binary.LittleEndian.Uint32(data[offset+8 : offset+12]),
		}
		mapList.List_[i] = mapItem
	}

	return mapList, nil
}

// 读取class
func readClassDef(data []byte, size uint32) ([]entity.ClassDef, error) {

	if size*32 > (uint32)(len(data)) {
		return nil, errors.New("invalid class offset")
	}
	debugPrint("class size %d \n", size)
	classes := make([]entity.ClassDef, size)

	for i := uint32(0); i < size; i++ {
		offset := int(i) * 32
		item := entity.ClassDef{
			Class_idx_:         binary.LittleEndian.Uint16(data[offset : offset+2]),
			Pad1_:              binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
			Access_flags_:      binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
			Superclass_idx_:    binary.LittleEndian.Uint16(data[offset+8 : offset+10]),
			Pad2_:              binary.LittleEndian.Uint16(data[offset+10 : offset+12]),
			Interfaces_off_:    binary.LittleEndian.Uint32(data[offset+12 : offset+16]),
			Source_file_idx_:   binary.LittleEndian.Uint32(data[offset+16 : offset+20]),
			Annotations_off_:   binary.LittleEndian.Uint32(data[offset+20 : offset+24]),
			Class_data_off_:    binary.LittleEndian.Uint32(data[offset+24 : offset+28]),
			Static_values_off_: binary.LittleEndian.Uint32(data[offset+28 : offset+32]),
		}
		classes[i] = item
	}
	return classes, nil
}

// 读取class data
func readClassDataItem(data []byte) (entity.ClassDataItem, error) {

	classDataItem := entity.ClassDataItem{}
	start := 0
	r, l := DecodeULEB128(data[start:])
	classDataItem.StaticFieldsSize = r
	start += l
	r, l = DecodeULEB128(data[start:])
	classDataItem.InstanceFieldsSize = r
	start += l
	r, l = DecodeULEB128(data[start:])
	classDataItem.DirectMethodsSize = r
	start += l
	r, l = DecodeULEB128(data[start:])
	classDataItem.VirtualMethodsSize = r
	start += l

	if 16+classDataItem.StaticFieldsSize*8+classDataItem.InstanceFieldsSize*8+classDataItem.DirectMethodsSize*12+classDataItem.VirtualMethodsSize*12 > (uint32)(len(data)) {
		return entity.ClassDataItem{}, errors.New("invalid size")
	}
	classDataItem.StaticFields = make([]entity.DexField, classDataItem.StaticFieldsSize)

	for i := uint32(0); i < classDataItem.StaticFieldsSize; i++ {
		item := entity.DexField{}
		item.FieldIdx, l = DecodeULEB128(data[start:])
		start += l
		item.AccessFlags, l = DecodeULEB128(data[start:])
		start += l
		classDataItem.StaticFields[i] = item
	}
	classDataItem.InstanceFields = make([]entity.DexField, classDataItem.InstanceFieldsSize)
	for i := uint32(0); i < classDataItem.InstanceFieldsSize; i++ {
		item := entity.DexField{}
		item.FieldIdx, l = DecodeULEB128(data[start:])
		start += l
		item.AccessFlags, l = DecodeULEB128(data[start:])
		start += l
		classDataItem.InstanceFields[i] = item
	}
	classDataItem.DirectMethods = make([]entity.MethodDef, classDataItem.DirectMethodsSize)
	for i := uint32(0); i < classDataItem.DirectMethodsSize; i++ {
		item := entity.MethodDef{}
		item.MethodIdx, l = DecodeULEB128(data[start:])
		start += l
		item.AccessFlags, l = DecodeULEB128(data[start:])
		start += l
		item.CodeOff, l = DecodeULEB128(data[start:])
		start += l
		classDataItem.DirectMethods[i] = item
	}
	classDataItem.VirtualMethods = make([]entity.MethodDef, classDataItem.VirtualMethodsSize)
	for i := uint32(0); i < classDataItem.VirtualMethodsSize; i++ {
		item := entity.MethodDef{}
		item.MethodIdx, l = DecodeULEB128(data[start:])
		start += l
		item.AccessFlags, l = DecodeULEB128(data[start:])
		start += l
		item.CodeOff, l = DecodeULEB128(data[start:])
		start += l
		classDataItem.VirtualMethods[i] = item
	}
	return classDataItem, nil
}

func ReadMethodCode(dex *entity.DexFile, methodId uint32, classdef entity.ClassDef) (byteCodeItem entity.MethodCodeItem, err error) {
	for methodIdex := range classdef.ClassDataItem.DirectMethods {
		if classdef.ClassDataItem.DirectMethods[methodIdex].MethodIdx == methodId {
			offset := classdef.ClassDataItem.DirectMethods[methodIdex].CodeOff - dex.Header.HeaderSize
			data := dex.Oridata[offset:]
			item := entity.MethodCodeItem{
				RegistersSize: binary.LittleEndian.Uint16(data[0:2]),
				InsSize:       binary.LittleEndian.Uint16(data[2:4]),
				OutsSize:      binary.LittleEndian.Uint16(data[4:6]),
				TriesSize:     binary.LittleEndian.Uint16(data[6:8]),
				DebbugInfoOff: binary.LittleEndian.Uint32(data[8:12]),
				InsnsSize:     binary.LittleEndian.Uint32(data[12:16]),
			}
			item.Insns = make([]uint16, item.InsnsSize)
			for i := 0; i < int(item.InsnsSize); i++ {
				item.Insns[i] = binary.LittleEndian.Uint16(data[16+i*2 : 18+i*2])
			}
			return item, nil
		}
	}
	for methodIdex := range classdef.ClassDataItem.VirtualMethods {
		if classdef.ClassDataItem.VirtualMethods[methodIdex].MethodIdx == methodId {
			offset := classdef.ClassDataItem.VirtualMethods[methodIdex].CodeOff - dex.Header.HeaderSize
			data := dex.Oridata[offset:]
			item := entity.MethodCodeItem{
				RegistersSize: binary.LittleEndian.Uint16(data[0:2]),
				InsSize:       binary.LittleEndian.Uint16(data[2:4]),
				OutsSize:      binary.LittleEndian.Uint16(data[4:6]),
				TriesSize:     binary.LittleEndian.Uint16(data[6:8]),
				DebbugInfoOff: binary.LittleEndian.Uint32(data[8:12]),
				InsnsSize:     binary.LittleEndian.Uint32(data[12:16]),
			}
			item.Insns = make([]uint16, item.InsnsSize)
			for i := 0; i < int(item.InsnsSize); i++ {
				item.Insns[i] = binary.LittleEndian.Uint16(data[16+i*2 : 18+i*2])
			}
			return item, nil
		}
	}
	return entity.MethodCodeItem{}, errors.New("not found")
}

// 读取type ID
func readTypeIds(data []byte, size uint32) ([]uint32, error) {
	typeIds := make([]uint32, size)

	for i := uint32(0); i < size; i++ {
		offset := i * 4 // 每个ID 占 4 字节
		if offset+4 > (uint32)(len(data)) {
			return nil, errors.New("invalid string ID offset")
		}
		typeIds[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}
	return typeIds, nil
}

// 读取方法 ID
func readMethodIds(data []byte, size uint32) ([]entity.MethodIdDef, error) {
	if size*8 > (uint32)(len(data)) {
		return nil, errors.New("invalid class offset")
	}
	debugPrint("class size %d \n", size)
	classes := make([]entity.MethodIdDef, size)

	for i := uint32(0); i < size; i++ {
		offset := int(i) * 8
		item := entity.MethodIdDef{
			Class_idx_: binary.LittleEndian.Uint16(data[offset : offset+2]),
			Proto_idx_: binary.LittleEndian.Uint16(data[offset+2 : offset+4]),
			Name_idx_:  binary.LittleEndian.Uint32(data[offset+4 : offset+8]),
		}
		classes[i] = item
	}
	return classes, nil
}

// 读取字符串 ID
func readStringIds(data []byte, size uint32) ([]uint32, error) {
	stringIds := make([]uint32, size)

	for i := uint32(0); i < size; i++ {
		offset := i * 4 // 每个字符串 ID 占 4 字节
		if offset+4 > (uint32)(len(data)) {
			return nil, errors.New("invalid string ID offset")
		}
		stringIds[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}
	return stringIds, nil
}

// LEB128 解码，返回值和读取的字节数
func DecodeULEB128(data []byte) (uint32, int) {
	var result uint32
	var shift uint
	var bytesRead int
	for {
		byteVal := data[bytesRead]
		result |= (uint32(byteVal) & 0x7F) << shift
		bytesRead++
		if byteVal&0x80 == 0 {
			break
		}
		shift += 7
	}
	return result, bytesRead
}
func ReadStringData(data []byte) (string, error) {

	// 读取字符串长度（LEB128 编码）
	leb128Length, bytesRead := DecodeULEB128(data[:])
	if bytesRead > 3 {
		return "", errors.New("invalid ULEB128 ")
	}
	offset := uint32(bytesRead)

	//debugPrint("str length %d\n", leb128Length)

	if offset+(uint32)(leb128Length) > uint32(len(data)) {
		return "", errors.New("invalid string data length")
	}

	// 读取实际的字符串内容
	stringData := data[offset : offset+(uint32)(leb128Length)]

	if idx := bytes.IndexByte(stringData, 0); idx != -1 {
		// 截断到 \0 之前的部分
		return string(stringData[:idx]), nil
	}

	return string(stringData), nil
}
func checkMap(dex *entity.DexFile) bool {
	mapOff := dex.Header.MapOff - dex.Header.HeaderSize
	data := dex.Oridata[mapOff:]
	mapList, err := byteSliceToMapList(data)

	if err != nil {
		return false
	}
	debugPrint("map item size %d \n", mapList.Size_)
	dex.MapList = mapList
	return true
}
func Verify(dex *entity.DexFile) bool {
	if !isMagicValid(dex.Header.Magic[:]) {
		return false
	}
	if !isVersionValid(dex.Header.Version[:]) {
		return false
	}
	if !checkHeader(dex) {
		return false
	}
	if !checkMap((dex)) {
		return false
	}
	stringOff := dex.Header.StringIdsOff - dex.Header.HeaderSize
	data := dex.Oridata[stringOff:]
	ids, err := readStringIds(data, dex.Header.StringIdsSize)
	if err != nil {
		return false
	}
	dex.StringIds = ids

	typeOff := dex.Header.TypeIdsOff - dex.Header.HeaderSize
	data = dex.Oridata[typeOff:]
	ids, err = readTypeIds(data, dex.Header.TypeIdsSize)
	if err != nil {
		return false
	}
	dex.Typeids = ids

	classOff := dex.Header.ClassDefsOff - dex.Header.HeaderSize
	data = dex.Oridata[classOff:]
	classes, err := readClassDef(data, dex.Header.ClassDefsSize)
	if err != nil {
		return false
	}
	dex.ClassDef = classes

	methodOff := dex.Header.MethodIdsOff - dex.Header.HeaderSize
	data = dex.Oridata[methodOff:]
	methods, err := readMethodIds(data, dex.Header.MethodIdsSize)
	if err != nil {
		return false
	}
	dex.MethodIds = methods

	dex.ValidDex = true
	return true
}
func convertToDexClassName(className string) string {
	// 将 . 替换为 /
	dexClassName := strings.ReplaceAll(className, ".", "/")
	// 添加 L 前缀和 ; 后缀
	dexClassName = "L" + dexClassName + ";"
	return dexClassName
}
func convertToClassName(className string) string {
	// 将 / 替换为 .
	dexClassName := strings.ReplaceAll(className, "/", ".")
	dexClassName = strings.TrimPrefix(dexClassName, "L")
	// 删除后缀 ;
	dexClassName = strings.TrimSuffix(dexClassName, ";")
	return dexClassName
}
func GetClassDef(fullClassName string, dex *entity.DexFile) (entity.ClassDef, error) {
	if !dex.ValidDex {
		return entity.ClassDef{}, fmt.Errorf("not a vaild dex")
	}
	classes := dex.ClassDef
	var dexClassName = convertToDexClassName(fullClassName)
	for index := range dex.ClassDef {
		classdef := classes[index]
		// debugPrint("class id to type %d\n",.Class_idx_)
		// debugPrint("type id to strid %d\n", dex.Typeids[classes[index].Class_idx_])
		// debugPrint("str id to offset %d\n", dex.StringIds[dex.Typeids[classes[index].Class_idx_]])
		data := dex.Oridata[dex.StringIds[dex.Typeids[classdef.Class_idx_]]-dex.Header.HeaderSize:]
		str, err := ReadStringData(data)
		if err == nil && dexClassName == str {
			classdef.ClassName = fullClassName
			data := dex.Oridata[dex.StringIds[dex.Typeids[classdef.Superclass_idx_]]-dex.Header.HeaderSize:]
			classdef.SupperClassName, _ = ReadStringData(data)
			classdef.SupperClassName = convertToClassName(classdef.SupperClassName)
			debugPrint("class id %x name %s\n", classdef.Class_idx_, str)
			data = dex.Oridata[classdef.Class_data_off_-dex.Header.HeaderSize:]
			classdef.ClassDataItem, _ = readClassDataItem(data)
			return classdef, nil
		}
	}
	return entity.ClassDef{}, fmt.Errorf("not found")
}

func GetClassAccessString(classDef entity.ClassDef) string {
	flags := classDef.Access_flags_
	var accessFlags []string

	if flags&entity.ACC_PUBLIC != 0 {
		accessFlags = append(accessFlags, "public")
	}
	if flags&entity.ACC_PRIVATE != 0 {
		accessFlags = append(accessFlags, "private")
	}
	if flags&entity.ACC_PROTECTED != 0 {
		accessFlags = append(accessFlags, "protected")
	}
	if flags&entity.ACC_STATIC != 0 {
		accessFlags = append(accessFlags, "static")
	}
	if flags&entity.ACC_FINAL != 0 {
		accessFlags = append(accessFlags, "final")
	}
	if flags&entity.ACC_SYNCHRONIZED != 0 {
		accessFlags = append(accessFlags, "synchronized")
	}
	if flags&entity.ACC_VOLATILE != 0 {
		accessFlags = append(accessFlags, "volatile")
	}
	if flags&entity.ACC_TRANSIENT != 0 {
		accessFlags = append(accessFlags, "transient")
	}
	if flags&entity.ACC_INTERFACE != 0 {
		accessFlags = append(accessFlags, "interface")
	}
	if flags&entity.ACC_ABSTRACT != 0 {
		accessFlags = append(accessFlags, "abstract")
	}

	if len(accessFlags) == 0 {
		return "default"
	}

	return fmt.Sprintf("%v", accessFlags)
}

func GetMethodIdDef(method string, classid uint16, dex *entity.DexFile) (entity.MethodIdDef, error) {
	if !dex.ValidDex {
		return entity.MethodIdDef{}, fmt.Errorf("not a vaild dex")
	}
	methods := dex.MethodIds
	//var dexClassName = convertToDexClassName(fullClassName)
	for index := range dex.MethodIds {
		methodef := methods[index]
		if methodef.Class_idx_ != classid {
			continue
		}
		// debugPrint("class id to type %d\n",.Class_idx_)
		// debugPrint("type id to strid %d\n", dex.Typeids[classes[index].Class_idx_])
		// debugPrint("str id to offset %d\n", dex.StringIds[dex.Typeids[classes[index].Class_idx_]])
		data := dex.Oridata[dex.StringIds[methodef.Name_idx_]-dex.Header.HeaderSize:]
		str, err := ReadStringData(data)
		if err == nil && method == str {
			methodef.MethodName = method
			return methodef, nil
		}
	}
	return entity.MethodIdDef{}, fmt.Errorf("not found")
}

func GetMethodId(method string, classid uint16, dex *entity.DexFile) (uint32, error) {
	if !dex.ValidDex {
		return 0, fmt.Errorf("not a vaild dex")
	}
	methods := dex.MethodIds
	for index := range dex.MethodIds {
		methodef := methods[index]
		if methodef.Class_idx_ != classid {
			continue
		}
		data := dex.Oridata[dex.StringIds[methodef.Name_idx_]-dex.Header.HeaderSize:]
		str, err := ReadStringData(data)
		if err == nil && method == str {
			return uint32(index), nil
		}
	}
	return 0, fmt.Errorf("not found")
}

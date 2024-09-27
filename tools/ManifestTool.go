package tools

//https://bbs.kanxue.com/thread-280251.htm

import (
	"apkgo/entity"
	"container/list"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"
)

var DebugFlag = false

func debugPrint(format string, args ...interface{}) {
	if DebugFlag {
		fmt.Printf(format, args...)
	}
}

// 根据输入的文件，返回数据对象，需要外部释放
func ReadManifest(mFile string) (*entity.ManifestData, error) {

	file, err := os.Open(mFile)
	if err != nil {
		debugPrint("Error opening AndroidManifest.xml:%s", err)
		return nil, fmt.Errorf("AndroidManifest can not open")
	}
	defer file.Close()

	data := &entity.ManifestData{
		OtherChunks:    list.New(),
		Activity:       make(map[string]bool),
		UsesPermission: list.New(),
	}

	err = parseXML(file, data)

	return data, err
}

// 原始数据是utf16
func getUtf16StringByIndex(index uint32, data *entity.ManifestData) string {
	if index < data.StringChunk.ScStringCount {
		var builder strings.Builder

		for _, r := range data.ScItems[index].Content {
			builder.WriteByte(r.C1) // 使用 WriteRune 来写入宽字符
			builder.WriteByte(r.C2)
		}
		return builder.String() // 返回构建的字符串
	}

	return ""
}

func getUtf8StringByIndex(index uint32, data *entity.ManifestData) string {
	original := getUtf16StringByIndex(index, data)
	var utf16Chars []uint16
	for i := 0; i < len(original); i += 2 {
		// 组合 C1 和 C2 字节
		if i+1 < len(original) {
			utf16Char := uint16(original[i+1])<<8 | uint16(original[i])
			utf16Chars = append(utf16Chars, utf16Char)
		}
	}

	return string(utf16.Decode(utf16Chars))
}

func parseXML(file *os.File, data *entity.ManifestData) error {
	const scStart = 0x8

	// 读Header
	err := binary.Read(file, binary.LittleEndian, &data.Header)
	if err != nil {
		return err
	}
	debugPrint("restype %d headSize %d fileSize %d\n", data.Header.ResType, data.Header.HeaderSize, data.Header.Filesize)
	// 读StringChunk头
	err = binary.Read(file, binary.LittleEndian, &data.StringChunk)
	if err != nil {
		return err
	}
	debugPrint("strings count %d\n", data.StringChunk.ScStringCount)
	// 读StringPool里的全部偏移量
	if data.StringChunk.ScStringCount != 0 {
		data.ScStringOffsets = make([]uint32, data.StringChunk.ScStringCount)
		data.ScItems = make([]entity.STRING_ITEM, data.StringChunk.ScStringCount)
	}
	for i := 0; i < (int)(data.StringChunk.ScStringCount); i++ {
		err = binary.Read(file, binary.LittleEndian, &data.ScStringOffsets[i])
		if err != nil {
			return err
		}
	}

	// 读StylePool里的全部偏移量
	if data.StringChunk.ScStyleCount != 0 {
		data.ScStringOffsets = make([]uint32, data.StringChunk.ScStyleCount)
	}
	for i := 0; i < (int)(data.StringChunk.ScStyleCount); i++ {
		err = binary.Read(file, binary.LittleEndian, &data.ScStringOffsets[i])
		if err != nil {
			return err
		}
	}

	// 读取StringPool里的全部Item
	for i := 0; i < (int)(data.StringChunk.ScStringCount); i++ {
		addr := scStart + data.StringChunk.ScStringPoolOffset + data.ScStringOffsets[i]
		var sfsize uint16
		_, err = file.Seek(int64(addr), io.SeekStart)
		if err != nil {
			return err
		}
		err = binary.Read(file, binary.LittleEndian, &sfsize)
		if err != nil {
			return err
		}
		data.ScItems[i].SfSize = sfsize
		if sfsize > 0 {
			data.ScItems[i].Content = make([]entity.ONECHAR, sfsize)
			err = binary.Read(file, binary.LittleEndian, &data.ScItems[i].Content)
			if err != nil {
				return err
			}
		}
		err = binary.Read(file, binary.LittleEndian, &data.ScItems[i].SfEnd)
		if err != nil {
			return err
		}
	}

	// 读取Resource Chunks
	err = binary.Read(file, binary.LittleEndian, &data.ResChunk.ResType)
	if err != nil {
		return err
	}
	if data.ResChunk.ResType != 0x180 {
		//file.Seek(2, io.SeekCurrent)
		binary.Read(file, binary.LittleEndian, &data.ResChunk.ResType)
		if data.ResChunk.ResType != 0x180 {
			return fmt.Errorf("error res chunk type")
		}
	}
	err = binary.Read(file, binary.LittleEndian, &data.ResChunk.HeaderSize)
	if err != nil {
		return err
	}
	err = binary.Read(file, binary.LittleEndian, &data.ResChunk.RcSize)
	if err != nil {
		return err
	}
	if data.ResChunk.RcSize != 0 {
		data.ResChunk.ResItems = make([]uint32, (data.ResChunk.RcSize-8)/4)
		for i := 0; i < int(data.ResChunk.RcSize-8)/4; i++ {
			err = binary.Read(file, binary.LittleEndian, &data.ResChunk.ResItems[i])
			if err != nil {
				return err
			}
		}
	}
	// 读取剩余的Chunks
	var lastKey = ""
	for {
		var tag uint32
		err = binary.Read(file, binary.LittleEndian, &tag)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		file.Seek(-4, io.SeekCurrent)
		if tag == entity.START_NAMESPACE_CHUNK {
			var startNSChunk entity.SNCHUNK
			err = binary.Read(file, binary.LittleEndian, &startNSChunk)
			if err != nil {
				return err
			}
			debugPrint("start namespace line %d index %d %s\n", startNSChunk.SncLineNumber, startNSChunk.SncUri, getUtf8StringByIndex(startNSChunk.SncUri, data))
			data.OtherChunks.PushBack(&startNSChunk)
		} else if tag == entity.END_NAMESPACE_CHUNK {
			var endNSChunk entity.ENCHUNK
			err = binary.Read(file, binary.LittleEndian, &endNSChunk)
			if err != nil {
				return err
			}
			debugPrint("end namespace line %d index %d %s\n", endNSChunk.EncLineNumber, endNSChunk.EncUri, getUtf8StringByIndex(endNSChunk.EncUri, data))
			data.OtherChunks.PushBack(&endNSChunk)
		} else if tag == entity.START_TAG_CHUNK {
			var startTagChunk entity.STCHUNK
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.ResType)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.HeaderSize)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcSize)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcLineNumber)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcComment)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcNamespaceUri)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcName)
			if err != nil {
				return err
			}
			tagName := getUtf8StringByIndex(startTagChunk.StcName, data)
			debugPrint("startTagname index %d %s\n", startTagChunk.StcName, tagName)
			var isManifest = false
			if tagName == "manifest" {
				isManifest = true
			}
			var isPermission = false
			if tagName == "uses-permission" {
				isPermission = true
			}
			var isApplication = false
			if tagName == "application" {
				isApplication = true
			}
			var isActivity = false
			if tagName == "activity" {
				isActivity = true
			}
			var isAction = false
			if tagName == "action" {
				isAction = true
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcFlags)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcAttributeCount)
			if err != nil {
				return err
			}
			err = binary.Read(file, binary.LittleEndian, &startTagChunk.StcClassAttribute)
			if err != nil {
				return err
			}
			startTagChunk.AttributeChunk = make([]entity.ATTRIBUTECHUNK, startTagChunk.StcAttributeCount)
			for i := 0; i < int(startTagChunk.StcAttributeCount); i++ {
				err = binary.Read(file, binary.LittleEndian, &startTagChunk.AttributeChunk[i])
				if err != nil {
					return err
				}
				acName := getUtf8StringByIndex(startTagChunk.AttributeChunk[i].AcName, data)
				debugPrint("name index %d %s\n", startTagChunk.AttributeChunk[i].AcName, acName)
				acValue := getUtf8StringByIndex(startTagChunk.AttributeChunk[i].AcValueStr, data)
				debugPrint("value index %d %s\n", startTagChunk.AttributeChunk[i].AcValueStr, acValue)
				if isManifest && acName == "package" {
					data.PackageName = acValue
				}
				if isPermission && acName == "name" {
					data.UsesPermission.PushBack(acValue)
				}
				if isApplication && acName == "name" {
					data.Application = acValue
				}
				if isActivity && acName == "name" {
					data.Activity[acValue] = false
					lastKey = acValue
				}
				if isAction && acName == "name" {
					if acValue == "android.intent.action.MAIN" {
						data.Activity[lastKey] = true
					}
				}
			}
			data.OtherChunks.PushBack(&startTagChunk)
		} else if tag == entity.END_TAG_CHUNK {
			var endTagChunk entity.ETCHUNK
			err = binary.Read(file, binary.LittleEndian, &endTagChunk)
			if err != nil {
				return err
			}
			debugPrint("endtag name index %d %s\n", endTagChunk.EtcName, getUtf8StringByIndex(endTagChunk.EtcName, data))
			data.OtherChunks.PushBack(&endTagChunk)
		} else if tag == entity.TEXT_CHUNK {
			var textChunk entity.TEXTCHUNK
			err = binary.Read(file, binary.LittleEndian, &textChunk)
			if err != nil {
				return err
			}
			debugPrint("text name index %d %s\n", textChunk.TcName, getUtf8StringByIndex(textChunk.TcName, data))
			data.OtherChunks.PushBack(&textChunk)
		} else {
			return errors.New("unknown chunk")
		}
	}
}

func WriteManifest(path string, data *entity.ManifestData) error {
	// 打开文件准备写入，如果文件不存在则创建，存在则清空内容
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// 写入Header
	err = binary.Write(file, binary.LittleEndian, &data.Header)
	if err != nil {
		return err
	}

	// 写入String Chunk头
	err = binary.Write(file, binary.LittleEndian, &data.StringChunk)
	if err != nil {
		return err
	}

	// 写入scStringOffsets
	for i := 0; i < len(data.ScStringOffsets); i++ {
		err = binary.Write(file, binary.LittleEndian, &data.ScStringOffsets[i])
		if err != nil {
			return err
		}
	}

	// 写入scItems
	for i := 0; i < len(data.ScItems); i++ {
		err = binary.Write(file, binary.LittleEndian, &data.ScItems[i].SfSize)
		if err != nil {
			return err
		}
		for j := 0; j < len(data.ScItems[i].Content); j++ {
			err = binary.Write(file, binary.LittleEndian, &data.ScItems[i].Content[j])
			if err != nil {
				return err
			}
		}
		err = binary.Write(file, binary.LittleEndian, &data.ScItems[i].SfEnd)
		if err != nil {
			return err
		}
	}

	// 写入Resource Chunks
	err = binary.Write(file, binary.LittleEndian, &data.ResChunk.ResType)
	if err != nil {
		return err
	}
	err = binary.Write(file, binary.LittleEndian, &data.ResChunk.RcSize)
	if err != nil {
		return err
	}
	for i := 0; i < int(data.ResChunk.RcSize/4-2); i++ {
		err = binary.Write(file, binary.LittleEndian, &data.ResChunk.ResItems[i])
		if err != nil {
			return err
		}
	}

	// 写入剩余的chunks
	for chunk := data.OtherChunks.Front(); chunk != nil; chunk = chunk.Next() {
		switch value := chunk.Value.(type) {
		case *entity.ENCHUNK:
			err = binary.Write(file, binary.LittleEndian, value)
			if err != nil {
				return err
			}
		case *entity.ETCHUNK:
			err = binary.Write(file, binary.LittleEndian, value)
			if err != nil {
				return err
			}
		case *entity.TEXTCHUNK:
			err = binary.Write(file, binary.LittleEndian, value)
			if err != nil {
				return err
			}
		case *entity.SNCHUNK:
			err = binary.Write(file, binary.LittleEndian, value)
			if err != nil {
				return err
			}
		case *entity.STCHUNK:
			err = binary.Write(file, binary.LittleEndian, value.ResType)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.HeaderSize)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcSize)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcLineNumber)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcComment)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcNamespaceUri)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcName)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcFlags)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcAttributeCount)
			if err != nil {
				return err
			}
			err = binary.Write(file, binary.LittleEndian, value.StcClassAttribute)
			if err != nil {
				return err
			}
			for i := 0; i < int(value.StcAttributeCount); i++ {
				err = binary.Write(file, binary.LittleEndian, value.AttributeChunk[i])
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

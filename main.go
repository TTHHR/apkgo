package main

import (
	"apkgo/entity"
	"apkgo/tools"
	"container/list"
	"fmt"
)

func main() {

	// 解析启动参数
	config, err := entity.ParseArgs()
	if err != nil {
		return
	}
	if config.ApkPath != "" {
		// 解压APK
		err = tools.Unzip(config.ApkPath, config.OutputDir)
		if err != nil {
			fmt.Println("Error during unzipping:", err)
			return
		} else {
			fmt.Println("APK successfully unpacked to", config.OutputDir)
			config.DexPath, _ = entity.GetDexFilesInDir(config.OutputDir)
		}
	}

	tools.DebugFlag = false

	manifestData, err := tools.ReadManifest(config.ManifestPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("package " + manifestData.PackageName)
	fmt.Println("Application " + manifestData.Application)
	for e := manifestData.UsesPermission.Front(); e != nil; e = e.Next() {
		permission := e.Value.(string)
		fmt.Println("Permission:", permission)
	}
	for key, value := range manifestData.Activity {
		fmt.Printf("Activity:%s isMain: %t\n", key, value)
	}
	// tools.WriteManifest("./newFile.xml", manifestData)
	var dexData = list.New()
	for strIndex := range config.DexPath {
		fmt.Print(config.DexPath[strIndex])
		data, err := tools.LoadDex(config.DexPath[strIndex])
		if err != nil {
			fmt.Println("dex decode error:", err)
		} else {
			if tools.Verify(data) {
				dexData.PushBack(data)
				fmt.Println(" valid dex")
			} else {
				fmt.Println("not a valid dex")
			}
		}
	}
	var class entity.ClassDef
	var classdex *entity.DexFile

	for e := dexData.Front(); e != nil; e = e.Next() {
		dex := e.Value.(*entity.DexFile)
		classDef, err := tools.GetClassDef(manifestData.Application, dex)
		if err != nil {
			fmt.Printf("%s not in %s %s\n", manifestData.Application, dex.FileName, err)
		} else {
			fmt.Printf("%s in %s\n", manifestData.Application, dex.FileName)
			fmt.Printf("assess flag %s\n", tools.GetClassAccessString(classDef))
			class = classDef
			classdex = dex
			break
		}
	}
	if class.ClassName != "" {
		methodid, _ := tools.GetMethodId("Test", class.Class_idx_, classdex)
		fmt.Println("run methond ", methodid)
		codeItem, _ := tools.ReadMethodCode(classdex, methodid, class)

		vm := tools.VM{
			Registers: make([]int, 16),
			PC:        0,
			Stack:     []int{},
		}
		vm.ExecuteBytecode(codeItem.Insns)
	}
}

package entity

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type CmdConfig struct {
	ApkPath      string
	OutputDir    string
	ManifestPath string
	DexPath      []string
}

// ParseArgs 解析控制台传递的参数
func ParseArgs() (CmdConfig, error) {
	apkPath := flag.String("apk", "", "Path to the APK file to be unpacked")
	outputDir := flag.String("out", "./testdata", "Directory to output the unpacked APK")

	flag.Parse()

	if *apkPath == "" && *outputDir == "" {
		fmt.Println("Error: APK or out path is required.")
		flag.Usage()
		return CmdConfig{}, fmt.Errorf("APK or out path is required")
	}
	var dexFiles []string
	if *outputDir != "" {
		d, err := GetDexFilesInDir(*outputDir)
		if err != nil {
			return CmdConfig{}, err
		}
		dexFiles = d
	}

	return CmdConfig{
		ApkPath:      *apkPath,
		OutputDir:    *outputDir,
		ManifestPath: *outputDir + "/AndroidManifest.xml",
		DexPath:      dexFiles,
	}, nil
}

func GetDexFilesInDir(dir string) ([]string, error) {
	// 读取目录中的所有文件和子目录
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取目录失败: %v", err)
	}

	var dexFiles []string
	for _, entry := range entries {
		// 检查是否是文件，并且扩展名是 .dex
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".dex") {
			dexFiles = append(dexFiles, dir+"/"+entry.Name())
		}
	}

	return dexFiles, nil
}

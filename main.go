package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"os"
	"strings"
	"time"

	"github.com/minio/sio"
)

func main() {
	//var str = "dfio.mp4.sio"
	//
	//print(str[:len(str)-4])

	encryptDir("/Users/devoty/Desktop/18/")
}

func encryptDir(path string) {
	fmt.Printf("current dir：%v\n", path)
	file, _ := os.Open(path)

	fileList, err := file.Readdir(-1)
	if err != nil {
		return
	}

	subDirs := make([]os.FileInfo, 0)

	for _, fileInfo := range fileList {

		if strings.EqualFold(".DS_Store", fileInfo.Name()) || strings.Contains(fileInfo.Name(), ".sio") {
			continue
		}

		// 先处理文件，后处理文件夹
		if !fileInfo.IsDir() {
			//encryptFile(fileInfo, file.Name())
			fmt.Printf("current file：%v\n", fileInfo.Name())
			continue
		}
		subDirs = append(subDirs, fileInfo)

	}

	for _, fileInfo := range subDirs {
		encryptDir(file.Name() + fileInfo.Name() + "/")
	}

}

func encryptFile(srcFile os.FileInfo, dir string) {
	encrypt(dir+srcFile.Name(), dir+srcFile.Name()+".sio")
}

func encrypt(srcPath, outPath string) {
	fmt.Printf("encrypting：%v\n", srcPath)
	startTime := time.Now()
	srcFile, _ := os.Open(srcPath)
	outFile, _ := os.Create(outPath)
	sio.Encrypt(outFile, srcFile, sio.Config{Key: configKey()})
	fmt.Printf("time consuming：%v\n", time.Since(startTime))
}

func decryptFile(srcFile os.FileInfo, dir string) {
	//strings.
	decrypt(dir+srcFile.Name(), dir+srcFile.Name())
}

func decrypt(srcPath, outPath string) {
	fmt.Printf("decrypting：%v\n", srcPath)
	startTime := time.Now()
	srcFile, _ := os.Open(srcPath)
	outFile, _ := os.Create(outPath)
	sio.Decrypt(outFile, srcFile, sio.Config{Key: configKey()})
	fmt.Printf("time consuming：%v\n", time.Since(startTime))
}

var mastery = "202105171992040719991012abcdefabcdef"
var nonce = "051704071012"

func configKey() []byte {

	mastery, err := hex.DecodeString(mastery)
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err)
		return nil
	}

	nonce, err := hex.DecodeString(nonce)
	if err != nil {
		fmt.Printf("Cannot decode hex key: %v", err)
		return nil
	}

	var key [32]byte
	kdf := hkdf.New(sha256.New, mastery, nonce[:], nil)
	if _, err = io.ReadFull(kdf, key[:]); err != nil {
		fmt.Printf("Failed to derive encryption key: %v", err)
		return nil
	}
	keys := make([]byte, len(key))
	copy(keys, key[:])
	return keys
}

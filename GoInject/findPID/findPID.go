package findPID

import (
   "fmt"
   "unsafe"
   "strings"
   "golang.org/x/sys/windows"
)

const procEntrySize = (uint32)(unsafe.Sizeof(windows.ProcessEntry32{}))

func ProcessID(name string) (uint32, error) {
   backslash := "\\"
   trimmedName := after(name,backslash)
   h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
   if e != nil { return 0, e }
   p := windows.ProcessEntry32{Size: procEntrySize}
   for {
      e := windows.Process32Next(h, &p)
      if e != nil { return 0, e }
      if windows.UTF16ToString(p.ExeFile[:]) == trimmedName {
         return p.ProcessID, nil
      }
   }
   return 0, fmt.Errorf("%q not found", name)
}

func after(value string, backslash string) string {
    //Check if characters exists in string

    if (strings.Contains(value, backslash)) {
    // Get substring after a string.
    pos := strings.LastIndex(value, backslash)
    if pos == -1 {
        return ""
    }
    adjustedPos := pos + len(backslash)
    if adjustedPos >= len(value) {
        return ""
    }
    return value[adjustedPos:len(value)]
} else {
    return value
}
}
package main

import (
	"fmt"
	"flag"
	"os"
	"GoInject/crypto"
)

func main(){
	shellcodeFilePtr := flag.String("shellcodeFile", "", "Full path to file to store the encrypted shellcode in.")
	shellcodePtr := flag.String("shellcode", "", "Shellcode in hex format")
	keyPtr := flag.String("key", "", "Encryption key")
	flag.Parse()

    fmt.Println(*shellcodeFilePtr)
    file, err := os.Create(*shellcodeFilePtr)
    if err != nil {
        fmt.Println(err)
        return
    }
    ciphertext := crypto.EncryptAES([]byte (*shellcodePtr), *keyPtr)
    
    write, err := file.WriteString(string(ciphertext))
    if err != nil {
        fmt.Println(err)
        file.Close()
        return
    }
    fmt.Println(write, "bytes written successfully")
    err = file.Close()
    if err != nil {
        fmt.Println(err)
        return
    }
}
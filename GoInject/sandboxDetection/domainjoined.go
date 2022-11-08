package sandboxDetection

import(
	"os"
	"strings"
)

func IsNotDomainJoined() bool {
	output, _ := os.Hostname()

	domain := strings.Split(output, " ")
    if len(domain) < 2 {
    	return true
    } 
    return false
}
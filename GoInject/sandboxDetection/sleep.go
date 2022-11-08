package sandboxDetection

import(
	"time"
)

func Sleep() bool{
	time1 := time.Now()
	time.Sleep(10 * time.Second)
	time2 := time.Now()
	delta := time2.Sub(time1)
	if delta < 9 {
		return true
	}
	return false
}
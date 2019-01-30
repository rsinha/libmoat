package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

func executeCmd(cmd, args string) string {
	Command := exec.Command(cmd, args)
	start := time.Now()
	out, _ := Command.Output()
	end := time.Now()
	fmt.Println(end.Sub(start).Seconds())
	return string(out)
}


func main()  {

	NoOfProcesses := os.Args[1]
	Compute := "/bin/sleep"
	Args := "1"

	NoOfTimes,_ := strconv.Atoi(NoOfProcesses)

	var wg sync.WaitGroup
	wg.Add(NoOfTimes)

	for i := 1; i <= NoOfTimes; i++ {
		go func(id int) {
			defer wg.Done()
			executeCmd(Compute, Args)
		}(i)
	}

	wg.Wait()

}

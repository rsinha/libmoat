package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

func executeCmd(idx string) string {
	args  := []string{"-c", "./config/barbican."+idx+".json", "-e", "enclave.signed.so", "-s", "42", "-l", "/tmp/barbican/"+idx}
	Command := exec.Command("./compute.out", args...)
	fmt.Println(Command)
	start := time.Now()
	out, _ := Command.Output()
	//fmt.Printf("%s\n",out)
	end := time.Now()
	fmt.Println(end.Sub(start).Seconds())
	return string(out)
}

func main()  {

	NoOfProcesses := os.Args[1]
	NoOfTimes,_ := strconv.Atoi(NoOfProcesses)

	var wg sync.WaitGroup
	wg.Add(NoOfTimes)

	for i := 1; i <= NoOfTimes; i++ {
		go func(id int) {
			defer wg.Done()
			idx :=  strconv.Itoa(id)
			executeCmd(idx)
		}(i)
	}

	wg.Wait()
}

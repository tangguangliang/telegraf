package procstat

import (
	"fmt"
	"os"
	"log"
	"os/exec"
	"strconv"
	"strings"

	"github.com/influxdata/telegraf/internal"
	psutil "github.com/shirou/gopsutil/v3/process"
)

// Implementation of PIDGatherer that execs pgrep to find processes
type pgrep struct {
	path string
}

func newPgrepFinder() (pidFinder, error) {
	path, err := exec.LookPath("pgrep")
	if err != nil {
		return nil, fmt.Errorf("could not find pgrep binary: %w", err)
	}
	return &pgrep{path}, nil
}

func (*pgrep) pidFile(path string) ([]pid, error) {
	var pids []pid
	pidString, err := os.ReadFile(path)
	if err != nil {
		return pids, fmt.Errorf("failed to read pidfile %q: %w",
			path, err)
	}
	processID, err := strconv.ParseInt(strings.TrimSpace(string(pidString)), 10, 32)
	if err != nil {
		return pids, err
	}
	pids = append(pids, pid(processID))
	return pids, nil
}

func (pg *pgrep) pattern(pattern string) ([]pid, error) {
	args := []string{"-x", pattern}
	return pg.find(args)
}

func (pg *pgrep) uid(user string) ([]pid, error) {
	args := []string{"-u", user}
	return pg.find(args)
}

func (pg *pgrep) fullPattern(pattern string) ([]pid, error) {
	args := []string{"-f", pattern}
	return pg.find(args)
}

func (pg *pgrep) exePattern(exe string, pattern string) ([]pid, error) {
	log.Printf("I! [pgrep] exePattern exe: %v, pattern: %v", exe, pattern)
	pids, err := pg.pattern(exe)
	if err != nil {
		return nil, err
	}
	log.Printf("I! [pgrep] exePattern pids: %v", pids)
	var matchingPids []pid
	for _, pid := range pids {
		p, err := psutil.NewProcess(int32(pid))
		if err != nil {
			continue
		}
		// 获取父ID，如果父ID已经在matchingPids中，则说明该进程为子进程，需要继续查找
		// parentID, err := p.Ppid()
		// log.Printf("I! [pgrep] exePattern pid: %v, parentID: %v", pid, parentID)
		// if err != nil {
		// 	continue
		// }
		// // 判断parentID是否在matchingPids中
    // isChild := false
    // for _, mp := range matchingPids {
		// 	if int32(mp) == parentID {
		// 			isChild = true
		// 			break
		// 	}
    // }
    // if isChild {
		// 	log.Printf("I! [pgrep] exePattern process %v is a child process, skipping", pid)
		// 	continue
    // }

		cmdlineStr, err := p.Cmdline()
		log.Printf("I! [pgrep] exePattern cmdlineStr: %v", cmdlineStr)
		if err != nil {
			log.Printf("I! [pgrep] exePattern not found cmdlineStr: %v", err)
			continue
		}
		// 如果cmdlineStr中包含pattern，则匹配成功
		if strings.Contains(cmdlineStr, pattern) {
			matchingPids = append(matchingPids, pid)
		}
	}
	log.Printf("I! [pgrep] exePattern matchingPids: %v", matchingPids)
	return matchingPids, nil
}

func (pg *pgrep) children(pid pid) ([]pid, error) {
	args := []string{"-P", strconv.FormatInt(int64(pid), 10)}
	return pg.find(args)
}

func (pg *pgrep) find(args []string) ([]pid, error) {
	// Execute pgrep with the given arguments
	buf, err := exec.Command(pg.path, args...).Output()
	if err != nil {
		// Exit code 1 means "no processes found" so we should not return
		// an error in this case.
		if status, _ := internal.ExitStatus(err); status == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("error running %q: %w", pg.path, err)
	}

	out := string(buf)
	// Parse the command output to extract the PIDs
	fields := strings.Fields(out)
	pids := make([]pid, 0, len(fields))
	for _, field := range fields {
		processID, err := strconv.ParseInt(field, 10, 32)
		if err != nil {
			return nil, err
		}
		pids = append(pids, pid(processID))
	}
	return pids, nil
}

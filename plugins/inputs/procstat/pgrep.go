package procstat

import (
	"fmt"
	"os"
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
		fmt.Printf("exePattern exe %v, pattern: %v\n", exe, pattern)
    pids, err := pg.pattern(exe)
    if err != nil {
        return nil, err
    }

    var matchingPids []pid
    for _, pid := range pids {
			p, err := psutil.NewProcess(int32(pid))
			if err != nil {
				continue
			}
			cmdlineArgs, err := p.CmdlineSlice()
			if err != nil {
				continue
			}
			for _, arg := range cmdlineArgs[1:] {
				fmt.Printf("cmdlineArgs %v, pattern: %v\n", arg, pattern)
				if strings.Contains(arg, pattern) {
					matchingPids = append(matchingPids, pid)
					break
				}
			}
    }
		fmt.Printf("exePattern exe %v, pattern: %v, matchingPids: %v\n", exe, pattern, matchingPids)
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
	fmt.Printf("find %q, args: %v, output: %s\n", pg.path, args, out)

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

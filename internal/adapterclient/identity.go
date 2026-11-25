package adapterclient

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"fplogin/internal/descriptortrust"
)

const adapterAccount = "fplogin-adapter"

func adapterIdentity() (uint32, uint32, error) {
	passwd, err := localAccount("/etc/passwd", 7)
	if err != nil {
		return 0, 0, err
	}
	group, err := localAccount("/etc/group", 4)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.ParseUint(passwd[2], 10, 32)
	gid, _ := strconv.ParseUint(group[2], 10, 32)
	validShell := passwd[6] == "/usr/bin/nologin" || passwd[6] == "/usr/sbin/nologin" || passwd[6] == "/sbin/nologin"
	if passwd[3] != group[2] || group[3] != "" || passwd[5] != "/" || !validShell {
		return 0, 0, ErrElevatedAdapter
	}
	return uint32(uid), uint32(gid), nil
}

func localAccount(path string, fieldCount int) ([]string, error) {
	if err := descriptortrust.ValidatePackagedFile(path); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrElevatedAdapter, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrElevatedAdapter, err)
	}
	var record []string
	counts := map[uint64]int{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != fieldCount {
			continue
		}
		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err == nil {
			counts[id]++
		}
		if fields[0] == adapterAccount {
			if record != nil || err != nil || id == 0 || id == 65534 || id == 1<<32-1 {
				return nil, ErrElevatedAdapter
			}
			record = fields
		}
	}
	if record == nil {
		return nil, ErrElevatedAdapter
	}
	id, _ := strconv.ParseUint(record[2], 10, 32)
	if counts[id] != 1 {
		return nil, ErrElevatedAdapter
	}
	return record, nil
}

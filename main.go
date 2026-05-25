package main

import (
	"cmp"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/coalaura/plain"
	"golang.org/x/sys/windows"
)

const (
	MaxProcs        = 16384
	EmergencyCommit = 0.92
	MinKillBytes    = 500 * (1 << 20)
	RequiredSamples = 4
	Interval        = 200 * time.Millisecond
)

var (
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procEnumProcesses        = modpsapi.NewProc("EnumProcesses")
	procGetPerformanceInfo   = modpsapi.NewProc("GetPerformanceInfo")
	procGetProcessMemoryInfo = modpsapi.NewProc("GetProcessMemoryInfo")

	procOpenProcess         = modkernel32.NewProc("OpenProcess")
	procCloseHandle         = modkernel32.NewProc("CloseHandle")
	procTerminateProcess    = modkernel32.NewProc("TerminateProcess")
	procOpenProcessToken    = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = modadvapi32.NewProc("GetTokenInformation")
	procEqualSid            = modadvapi32.NewProc("EqualSid")
)

// gost:preserve-layout
type performanceInformation struct {
	cb                uint32
	_                 uint32
	commitTotal       uintptr
	commitLimit       uintptr
	commitPeak        uintptr
	physicalTotal     uintptr
	physicalAvailable uintptr
	systemCache       uintptr
	kernelTotal       uintptr
	kernelPaged       uintptr
	kernelNonpaged    uintptr
	pageSize          uintptr
	handleCount       uint32
	processCount      uint32
	threadCount       uint32
	_                 uint32
}

// gost:preserve-layout
type processMemoryCountersEx struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

// gost:preserve-layout
type procStats struct {
	pid          uint32
	lastBytes    uint64
	currentBytes uint64
	firstSeen    int64
	lastSeen     int64
	isUserProc   bool
}

type logEvent struct {
	message [64]byte
	msgType int
	commit  float64
	bytes   uint64
	msgLen  int
	pid     uint32
}

var (
	myPid           uint32
	mySid           *windows.SID
	globalTokenUser *windows.Tokenuser

	pids            [MaxProcs]uint32
	cbNeeded        uint32
	tokenInfoBuffer [128]uintptr

	currentProcs []procStats
	nextProcs    []procStats

	logChan         = make(chan logEvent, 1024)
	pressureSamples int
)

func init() {
	procEnumProcesses.Find()
	procGetPerformanceInfo.Find()
	procGetProcessMemoryInfo.Find()
	procOpenProcess.Find()
	procCloseHandle.Find()
	procTerminateProcess.Find()
	procOpenProcessToken.Find()
	procGetTokenInformation.Find()
	procEqualSid.Find()
}

func main() {
	debug.SetMemoryLimit(32 << 20)

	initMySid()
	startLogger()

	currentProcs = make([]procStats, 0, MaxProcs)
	nextProcs = make([]procStats, 0, MaxProcs)

	sendMsg(0, "GOOM started. Monitoring memory pressure...")

	ticker := time.NewTicker(Interval)
	defer ticker.Stop()

	for range ticker.C {
		monitor()
	}
}

func monitor() {
	commitUsed, commitLimit, physTotal, _ := getSystemMemory()
	if commitLimit == 0 {
		return
	}

	// at least 2GB OR 5% of total commit, whichever is LARGER
	minHeadroom := uint64(2 << 30)
	if fivePercent := commitLimit / 20; fivePercent > minHeadroom {
		minHeadroom = fivePercent
	}

	systemUnderPressure := (commitLimit - commitUsed) < minHeadroom

	updateProcs()

	// single process eating absurd amount of RAM (> 60%) and still growing
	rogueLimit := (physTotal / 10) * 6

	var rogueFound bool

	for i := range currentProcs {
		proc := &currentProcs[i]
		if proc.isUserProc && proc.pid != myPid && proc.currentBytes > rogueLimit && proc.currentBytes > proc.lastBytes {
			rogueFound = true

			// getting dangerous
			if proc.lastBytes <= rogueLimit {
				event := logEvent{
					msgType: 1,
					pid:     proc.pid,
					commit:  float64(commitUsed) / float64(commitLimit),
					bytes:   proc.currentBytes,
				}

				select {
				case logChan <- event:
				default:
				}
			}

			break
		}
	}

	if systemUnderPressure || rogueFound {
		pressureSamples++
	} else {
		pressureSamples = 0
	}

	if pressureSamples >= RequiredSamples {
		victim := selectVictim(rogueLimit)
		if victim != nil {
			killProcess(victim.pid)

			logEv := logEvent{
				msgType: 2,
				pid:     victim.pid,
				commit:  float64(commitUsed) / float64(commitLimit),
				bytes:   victim.currentBytes,
			}

			select {
			case logChan <- logEv:
			default:
			}

			pressureSamples = 0
		}
	}
}

func updateProcs() {
	count := getPids()

	slices.Sort(count)

	count = slices.Compact(count)

	nextProcs = nextProcs[:0]

	now := time.Now().UnixNano()

	for _, pid := range count {
		if len(nextProcs) == cap(nextProcs) {
			break
		}

		idx, found := slices.BinarySearchFunc(currentProcs, pid, func(p procStats, t uint32) int {
			return cmp.Compare(p.pid, t)
		})

		var stats procStats

		if found {
			stats = currentProcs[idx]
			stats.lastBytes = stats.currentBytes
		} else {
			stats.pid = pid
			stats.firstSeen = now
			stats.isUserProc = isMyProcess(pid)
		}

		stats.lastSeen = now
		stats.currentBytes = getPrivateBytes(pid)

		nextProcs = append(nextProcs, stats)
	}

	currentProcs, nextProcs = nextProcs, currentProcs
}

func selectVictim(rogueLimit uint64) *procStats {
	var (
		victim   *procStats
		maxScore float64
	)

	for i := range currentProcs {
		proc := &currentProcs[i]
		if !proc.isUserProc || proc.pid == myPid {
			continue
		}

		if proc.currentBytes < MinKillBytes {
			continue
		}

		growth := max(0, float64(proc.currentBytes)-float64(proc.lastBytes))

		score := float64(proc.currentBytes) + growth*10.0

		if proc.currentBytes > rogueLimit && growth > 0 {
			score *= 100.0
		}

		if score > maxScore {
			maxScore = score
			victim = proc
		}
	}

	return victim
}

func getSystemMemory() (commitUsed, commitLimit, physicalTotal, physicalAvail uint64) {
	var info performanceInformation

	info.cb = uint32(unsafe.Sizeof(info))

	r1, _, _ := syscall.SyscallN(procGetPerformanceInfo.Addr(), uintptr(unsafe.Pointer(&info)), uintptr(info.cb))
	if r1 == 0 {
		return 0, 0, 0, 0
	}

	pageSize := uint64(info.pageSize)

	return uint64(info.commitTotal) * pageSize, uint64(info.commitLimit) * pageSize, uint64(info.physicalTotal) * pageSize, uint64(info.physicalAvailable) * pageSize
}

func getPids() []uint32 {
	r1, _, _ := syscall.SyscallN(procEnumProcesses.Addr(), uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)*4), uintptr(unsafe.Pointer(&cbNeeded)))
	if r1 == 0 {
		return pids[:0]
	}

	count := cbNeeded / 4

	if count > uint32(len(pids)) {
		count = uint32(len(pids))
	}

	return pids[:count]
}

func getPrivateBytes(pid uint32) uint64 {
	r1, _, _ := syscall.SyscallN(procOpenProcess.Addr(), windows.PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if r1 == 0 {
		return 0
	}

	handle := r1

	defer syscall.SyscallN(procCloseHandle.Addr(), handle)

	var counters processMemoryCountersEx

	counters.cb = uint32(unsafe.Sizeof(counters))

	r1, _, _ = syscall.SyscallN(procGetProcessMemoryInfo.Addr(), handle, uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb))
	if r1 == 0 {
		return 0
	}

	return uint64(counters.privateUsage)
}

func isMyProcess(pid uint32) bool {
	r1, _, _ := syscall.SyscallN(procOpenProcess.Addr(), windows.PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if r1 == 0 {
		return false
	}

	handle := r1

	defer syscall.SyscallN(procCloseHandle.Addr(), handle)

	var token uintptr

	r1, _, _ = syscall.SyscallN(procOpenProcessToken.Addr(), handle, windows.TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return false
	}

	defer syscall.SyscallN(procCloseHandle.Addr(), token)

	var retLen uint32

	r1, _, _ = syscall.SyscallN(
		procGetTokenInformation.Addr(),
		token,
		windows.TokenUser,
		uintptr(unsafe.Pointer(&tokenInfoBuffer[0])),
		uintptr(len(tokenInfoBuffer)*int(unsafe.Sizeof(tokenInfoBuffer[0]))),
		uintptr(unsafe.Pointer(&retLen)),
	)

	if r1 == 0 {
		return false
	}

	tokenUser := (*windows.Tokenuser)(unsafe.Pointer(&tokenInfoBuffer[0]))

	r1, _, _ = syscall.SyscallN(procEqualSid.Addr(), uintptr(unsafe.Pointer(mySid)), uintptr(unsafe.Pointer(tokenUser.User.Sid)))

	return r1 != 0
}

func killProcess(pid uint32) {
	r1, _, _ := syscall.SyscallN(procOpenProcess.Addr(), windows.PROCESS_TERMINATE, 0, uintptr(pid))
	if r1 == 0 {
		return
	}

	handle := r1

	defer syscall.SyscallN(procCloseHandle.Addr(), handle)

	syscall.SyscallN(procTerminateProcess.Addr(), handle, 1)
}

func initMySid() {
	myPid = uint32(os.Getpid())

	handle := windows.CurrentProcess()

	var token windows.Token

	err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		panic("failed to get process token: " + err.Error())
	}

	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		panic("failed to get token user: " + err.Error())
	}

	globalTokenUser = tokenUser
	mySid = tokenUser.User.Sid
}

func sendMsg(msgType int, text string) {
	var event logEvent

	event.msgType = msgType
	event.msgLen = copy(event.message[:], text)

	select {
	case logChan <- event:
	default:
	}
}

func startLogger() {
	pl := plain.New()

	path := "goom.log"

	home, err := os.UserHomeDir()
	if err == nil {
		path = filepath.Join(home, path)
	} else {
		pl.Warnf("Failed to get user home: %v\n", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		pl.Warnf("Failed to open log: %v\n", err)
	}

	go func() {
		if file != nil {
			defer file.Close()
		}

		var buf []byte

		for ev := range logChan {
			buf = buf[:0]

			switch ev.msgType {
			case 0:
				buf = append(buf, "INFO: "...)
			case 1:
				buf = append(buf, "WARN: "...)
			case 2:
				buf = append(buf, "KILL: "...)
			}

			if ev.msgLen > 0 {
				buf = append(buf, ev.message[:ev.msgLen]...)
			} else {
				buf = append(buf, "PID: "...)
				buf = strconv.AppendUint(buf, uint64(ev.pid), 10)

				buf = append(buf, " Commit: "...)
				buf = strconv.AppendFloat(buf, ev.commit*100, 'f', 2, 64)

				buf = append(buf, "% Mem: "...)
				buf = strconv.AppendUint(buf, ev.bytes/(1<<20), 10)
				buf = append(buf, " MB"...)
			}

			buf = append(buf, '\n')

			logStr := string(buf[:len(buf)-1])

			switch ev.msgType {
			case 0:
				pl.Println(logStr)
			case 1:
				pl.Warnln(logStr)
			case 2:
				pl.Errorln(logStr)
			}

			if file != nil {
				file.Write(buf)
			}
		}
	}()
}

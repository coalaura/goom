package main

import (
	"os"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

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

	procEnumProcesses              = modpsapi.NewProc("EnumProcesses")
	procGetPerformanceInfo         = modpsapi.NewProc("GetPerformanceInfo")
	procGetProcessMemoryInfo       = modpsapi.NewProc("GetProcessMemoryInfo")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")

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
	procQueryFullProcessImageNameW.Find()

	procOpenProcess.Find()
	procCloseHandle.Find()
	procTerminateProcess.Find()
	procOpenProcessToken.Find()
	procGetTokenInformation.Find()
	procEqualSid.Find()
}

func main() {
	mutexName, err := windows.UTF16PtrFromString("Local\\GoomSingleInstanceMutex")
	if err != nil {
		panic("failed to create mutex name: " + err.Error())
	}

	h, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		if err == windows.ERROR_ALREADY_EXISTS {
			windows.CloseHandle(h)

			pl.Errorln("GOOM is already running, exiting.")

			os.Exit(0)
		}

		panic("failed to create single instance mutex: " + err.Error())
	}

	defer windows.CloseHandle(h)

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
					msgType: 1, // WARN
					reason:  ReasonRogue,
					pid:     proc.pid,
					commit:  float64(commitUsed) / float64(commitLimit),
					bytes:   proc.currentBytes,
					name:    proc.name,
					nameLen: proc.nameLen,
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
		victim, reason := selectVictim(rogueLimit)
		if victim != nil {
			killProcess(victim.pid)

			logEv := logEvent{
				msgType: 2, // KILL
				reason:  reason,
				pid:     victim.pid,
				commit:  float64(commitUsed) / float64(commitLimit),
				bytes:   victim.currentBytes,
				name:    victim.name,
				nameLen: victim.nameLen,
			}

			select {
			case logChan <- logEv:
			default:
			}

			pressureSamples = 0
		}
	}
}

func selectVictim(rogueLimit uint64) (*procStats, LogReason) {
	var (
		victim     *procStats
		maxScore   float64
		bestReason LogReason
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

		sizeScore := float64(proc.currentBytes)
		growthScore := growth * 10.0
		score := sizeScore + growthScore

		var reason LogReason
		if growthScore > sizeScore {
			reason = ReasonRapidGrowth
		} else {
			reason = ReasonExcessiveSize
		}

		if proc.currentBytes > rogueLimit && growth > 0 {
			score *= 100.0
			reason = ReasonRogue
		}

		if score > maxScore {
			maxScore = score
			victim = proc
			bestReason = reason
		}
	}

	return victim, bestReason
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

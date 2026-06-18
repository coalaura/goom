package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/term"
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
	tokenInfoBuffer [128]uintptr

	currentProcs []procStats
	nextProcs    []procStats

	logChan         = make(chan logEvent, 1024)
	pressureSamples int

	scratchPerfInfo performanceInformation
	scratchCounters processMemoryCountersEx
	scratchUtf16Buf [512]uint16
	scratchToken    uintptr
	scratchTokenLen uint32
	scratchCbNeeded uint32
	scratchSize     uint32
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

var mutexName = [...]uint16{
	'G', 'l', 'o', 'b', 'a', 'l', '\\', 'G', 'o', 'o', 'm', 'S', 'i', 'n', 'g', 'l', 'e', 'I', 'n', 's', 't', 'a', 'n', 'c', 'e', 'M', 'u', 't', 'e', 'x', 0,
}

func main() {
	if len(os.Args) > 1 {
		handleFlags()
		return
	}

	h, err := windows.CreateMutex(nil, false, &mutexName[0])
	if err != nil {
		if err == windows.ERROR_ALREADY_EXISTS || err == windows.ERROR_ACCESS_DENIED {
			if h != 0 {
				windows.CloseHandle(h)
			}

			os.Stderr.WriteString("GOOM is already running, exiting.\n")

			os.Exit(0)
		}

		panic("failed to create single instance mutex: " + err.Error())
	}

	defer windows.CloseHandle(h)

	isService, err := svc.IsWindowsService()
	if err != nil {
		panic("failed to determine if running as service: " + err.Error())
	}

	if isService {
		err = svc.Run(serviceName, &goomService{})
		if err != nil {
			panic("failed to run service: " + err.Error())
		}

		return
	}

	debug.SetMemoryLimit(32 << 20)

	initMySid()
	startLogger(os.Stdout, term.IsTerminal(int(os.Stdout.Fd())))

	currentProcs = make([]procStats, 0, MaxProcs)
	nextProcs = make([]procStats, 0, MaxProcs)

	sendMsg(0, "GOOM started. Monitoring memory pressure...")

	ticker := time.NewTicker(Interval)
	defer ticker.Stop()

	for range ticker.C {
		monitor()
	}
}

func handleFlags() {
	switch os.Args[1] {
	case "--install":
		err := installService()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to install service: %v\n", err)

			os.Exit(1)
		}

		fmt.Println("Service installed and started successfully.")
	case "--uninstall":
		err := uninstallService()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to uninstall service: %v\n", err)

			os.Exit(1)
		}

		fmt.Println("Service uninstalled successfully.")
	default:
		fmt.Fprintf(os.Stderr, "unknown flag: %s\nUsage:\n  goom.exe [--install | --uninstall]\n", os.Args[1])

		os.Exit(1)
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

				sendEvent(event)
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
		victimIdx, reason := selectVictim(rogueLimit)
		if victimIdx >= 0 {
			victim := &currentProcs[victimIdx]

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

			sendEvent(logEv)

			pressureSamples = 0
		}
	}
}

func selectVictim(rogueLimit uint64) (int, LogReason) {
	var (
		maxScore   float64
		bestReason LogReason
		victimIdx  = -1
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
			victimIdx = i
			bestReason = reason
		}
	}

	return victimIdx, bestReason
}

func getSystemMemory() (commitUsed, commitLimit, physicalTotal, physicalAvail uint64) {
	scratchPerfInfo.cb = uint32(unsafe.Sizeof(scratchPerfInfo))

	r1, _, _ := syscall.SyscallN(procGetPerformanceInfo.Addr(), uintptr(unsafe.Pointer(&scratchPerfInfo)), uintptr(scratchPerfInfo.cb))
	if r1 == 0 {
		return 0, 0, 0, 0
	}

	pageSize := uint64(scratchPerfInfo.pageSize)

	return uint64(scratchPerfInfo.commitTotal) * pageSize, uint64(scratchPerfInfo.commitLimit) * pageSize, uint64(scratchPerfInfo.physicalTotal) * pageSize, uint64(scratchPerfInfo.physicalAvailable) * pageSize
}

func getPrivateBytes(pid uint32) uint64 {
	r1, _, _ := syscall.SyscallN(procOpenProcess.Addr(), windows.PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if r1 == 0 {
		return 0
	}

	handle := r1

	defer syscall.SyscallN(procCloseHandle.Addr(), handle)

	scratchCounters.cb = uint32(unsafe.Sizeof(scratchCounters))

	r1, _, _ = syscall.SyscallN(procGetProcessMemoryInfo.Addr(), handle, uintptr(unsafe.Pointer(&scratchCounters)), uintptr(scratchCounters.cb))
	if r1 == 0 {
		return 0
	}

	return uint64(scratchCounters.privateUsage)
}

package main

import (
	"cmp"
	"os"
	"slices"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gost:preserve-layout
type procStats struct {
	pid          uint32
	lastBytes    uint64
	currentBytes uint64
	firstSeen    int64
	lastSeen     int64
	isUserProc   bool
	name         [32]byte
	nameLen      int
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
			stats.nameLen = getProcessName(pid, &stats.name)
		}

		stats.lastSeen = now
		stats.currentBytes = getPrivateBytes(pid)

		nextProcs = append(nextProcs, stats)
	}

	currentProcs, nextProcs = nextProcs, currentProcs
}

func getProcessName(pid uint32, dest *[32]byte) int {
	r1, _, _ := syscall.SyscallN(procOpenProcess.Addr(), windows.PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if r1 == 0 {
		return 0
	}

	handle := r1

	defer syscall.SyscallN(procCloseHandle.Addr(), handle)

	var utf16Buf [260]uint16

	size := uint32(len(utf16Buf))

	r1, _, _ = syscall.SyscallN(
		procQueryFullProcessImageNameW.Addr(),
		handle,
		0,
		uintptr(unsafe.Pointer(&utf16Buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)

	if r1 == 0 || size == 0 {
		return 0
	}

	var start int

	for i := int(size) - 1; i >= 0; i-- {
		if utf16Buf[i] == '\\' || utf16Buf[i] == '/' {
			start = i + 1

			break
		}
	}

	var written int

	for i := start; i < int(size) && written < len(dest); i++ {
		char := utf16Buf[i]

		if char < 128 {
			dest[written] = byte(char)
		} else {
			dest[written] = '?'
		}

		written++
	}

	return written
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

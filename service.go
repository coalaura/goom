package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modwtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")
	moduserenv  = windows.NewLazySystemDLL("userenv.dll")

	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = modwtsapi32.NewProc("WTSQueryUserToken")
	procGetUserProfileDirectoryW     = moduserenv.NewProc("GetUserProfileDirectoryW")
)

const (
	serviceName  = "GoomService"
	displayName  = "GOOM Memory Monitor"
	description  = "Monitors system memory pressure and terminates runaway processes."
	cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
)

type goomService struct{}

type dynamicFileWriter struct {
	path string
	file *os.File
	mu   sync.Mutex
}

func (dfw *dynamicFileWriter) Write(p []byte) (n int, err error) {
	dfw.mu.Lock()
	defer dfw.mu.Unlock()

	if dfw.file == nil {
		return len(p), nil
	}

	return dfw.file.Write(p)
}

func (dfw *dynamicFileWriter) Redirect(path string) {
	dfw.mu.Lock()
	defer dfw.mu.Unlock()

	if path == dfw.path {
		return
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return
	}

	if dfw.file != nil {
		dfw.file.Close()
	}

	dfw.file = file
	dfw.path = path
}

func (dfw *dynamicFileWriter) Close() error {
	dfw.mu.Lock()
	defer dfw.mu.Unlock()

	if dfw.file != nil {
		err := dfw.file.Close()

		dfw.file = nil
		dfw.path = ""

		return err
	}

	return nil
}

func (m *goomService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	stopChan := make(chan struct{})

	go runMonitorLoop(stopChan)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		var breakOut bool

		cr := <-r

		switch cr.Cmd {
		case svc.Interrogate:
			changes <- cr.CurrentStatus
		case svc.Stop, svc.Shutdown:
			close(stopChan)

			breakOut = true
		default:
		}

		if breakOut {
			break
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	return
}

func runMonitorLoop(stopChan <-chan struct{}) {
	debug.SetMemoryLimit(32 << 20)

	initMySid()

	dw := &dynamicFileWriter{}

	updateActiveUser(dw)

	startLogger(dw, false)

	currentProcs = make([]procStats, 0, MaxProcs)
	nextProcs = make([]procStats, 0, MaxProcs)

	sendMsg(0, "GOOM service started. Monitoring memory pressure...")

	ticker := time.NewTicker(Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updateActiveUser(dw)

			monitor()
		case <-stopChan:
			sendMsg(0, "GOOM service stopping...")

			stopLogger()

			dw.Close()

			return
		}
	}
}

func getActiveConsoleUser() (*windows.SID, string, error) {
	r1, _, _ := syscall.SyscallN(procWTSGetActiveConsoleSessionId.Addr())
	if r1 == 0xFFFFFFFF {
		return nil, "", fmt.Errorf("no active console session")
	}

	sessionID := uint32(r1)

	var token windows.Token

	r1, _, errNo := syscall.SyscallN(procWTSQueryUserToken.Addr(), uintptr(sessionID), uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return nil, "", errNo
	}

	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get token user: %w", err)
	}

	sidCopy, err := tokenUser.User.Sid.Copy()
	if err != nil {
		return nil, "", fmt.Errorf("failed to copy SID: %w", err)
	}

	var profileDir [512]uint16

	size := uint32(len(profileDir))

	r1, _, err = syscall.SyscallN(
		procGetUserProfileDirectoryW.Addr(),
		uintptr(token),
		uintptr(unsafe.Pointer(&profileDir[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return nil, "", err
	}

	homeDir := windows.UTF16ToString(profileDir[:size])

	return sidCopy, homeDir, nil
}

func updateActiveUser(dw *dynamicFileWriter) {
	sid, home, err := getActiveConsoleUser()
	if err == nil {
		mySid = sid

		dw.Redirect(filepath.Join(home, "goom.log"))

		loadConfig(home)
	} else {
		if globalTokenUser != nil {
			mySid = globalTokenUser.User.Sid
		}

		home, err := os.UserHomeDir()
		if err == nil {
			dw.Redirect(filepath.Join(home, "goom.log"))

			loadConfig(home)
		}
	}
}

func installService() error {
	exepath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("access denied; please run this command from an elevated (Administrator) command prompt")
		}

		return err
	}

	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()

		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exepath, mgr.Config{
		DisplayName:  displayName,
		Description:  description,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return err
	}

	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("service registered but failed to start immediately: %w", err)
	}

	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("access denied; please run this command from an elevated (Administrator) command prompt")
		}

		return err
	}

	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}

	defer s.Close()

	stopService(s)

	err = s.Delete()
	if err != nil {
		return err
	}

	return nil
}

func restartService() error {
	m, err := mgr.Connect()
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("access denied; please run this command from an elevated (Administrator) command prompt")
		}

		return err
	}

	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}

	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("failed to query service status: %w", err)
	}

	if status.State != svc.Stopped {
		err = stopService(s)
		if err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}
	}

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func stopService(s *mgr.Service) error {
	status, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}

	timeout := time.Now().Add(10 * time.Second)

	for status.State != svc.Stopped {
		if time.Now().After(timeout) {
			return fmt.Errorf("timeout waiting for service to stop")
		}

		time.Sleep(300 * time.Millisecond)

		status, err = s.Query()
		if err != nil {
			return err
		}
	}

	return nil
}

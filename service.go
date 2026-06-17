package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	modwtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")

	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryUserToken            = modwtsapi32.NewProc("WTSQueryUserToken")
)

const (
	serviceName  = "GoomService"
	displayName  = "GOOM Memory Monitor"
	description  = "Monitors system memory pressure and terminates runaway processes."
	cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
)

type goomService struct{}

func (m *goomService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	stopChan := make(chan struct{})

	go runMonitorLoop(stopChan)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		var breakOut bool

		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				close(stopChan)

				breakOut = true
			default:
			}
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
	startLogger()

	currentProcs = make([]procStats, 0, MaxProcs)
	nextProcs = make([]procStats, 0, MaxProcs)

	sendMsg(0, "GOOM service started. Monitoring memory pressure...")

	ticker := time.NewTicker(Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updateActiveUser()
			monitor()
		case <-stopChan:
			sendMsg(0, "GOOM service stopping...")

			return
		}
	}
}

func getActiveConsoleUser() (*windows.SID, error) {
	r1, _, _ := syscall.SyscallN(procWTSGetActiveConsoleSessionId.Addr())
	if r1 == 0xFFFFFFFF {
		return nil, fmt.Errorf("no active console session")
	}

	sessionID := uint32(r1)

	var token windows.Token

	r1, _, errNo := syscall.SyscallN(procWTSQueryUserToken.Addr(), uintptr(sessionID), uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return nil, errNo
	}

	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get token user: %w", err)
	}

	sidCopy, err := tokenUser.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("failed to copy SID: %w", err)
	}

	return sidCopy, nil
}

func updateActiveUser() {
	sid, err := getActiveConsoleUser()
	if err == nil {
		mySid = sid
	} else {
		if globalTokenUser != nil {
			mySid = globalTokenUser.User.Sid
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

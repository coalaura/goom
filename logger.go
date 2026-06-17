package main

import (
	"os"
	"path/filepath"
	"strconv"
)

type LogReason uint8

const (
	ReasonNone LogReason = iota
	ReasonRogue
	ReasonExcessiveSize
	ReasonRapidGrowth
)

type logEvent struct {
	message [64]byte
	name    [32]byte
	msgType int
	commit  float64
	bytes   uint64
	msgLen  int
	nameLen int
	pid     uint32
	reason  LogReason
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
	path := "goom.log"

	home, err := os.UserHomeDir()
	if err == nil {
		path = filepath.Join(home, path)
	} else {
		os.Stderr.WriteString("Failed to get user home\n")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		os.Stderr.WriteString("Failed to open log file\n")
	}

	go func() {
		if file != nil {
			defer file.Close()
		}

		buf := make([]byte, 0, 512)

		for ev := range logChan {
			buf = buf[:0]

			switch ev.msgType {
			case 0:
				buf = append(buf, "[INFO] "...)
			case 1:
				buf = append(buf, "[WARN] "...)
			case 2:
				buf = append(buf, "[KILL] "...)
			}

			if ev.msgLen > 0 {
				buf = append(buf, ev.message[:ev.msgLen]...)
			} else {
				buf = append(buf, "PID "...)
				buf = strconv.AppendUint(buf, uint64(ev.pid), 10)

				if ev.nameLen > 0 {
					buf = append(buf, " ("...)
					buf = append(buf, ev.name[:ev.nameLen]...)
					buf = append(buf, ')')
				}

				buf = append(buf, " | Mem: "...)
				buf = strconv.AppendUint(buf, ev.bytes/(1<<20), 10)
				buf = append(buf, " MB | Commit: "...)
				buf = strconv.AppendFloat(buf, ev.commit*100, 'f', 1, 64)
				buf = append(buf, "% | "...)

				switch ev.reason {
				case ReasonRogue:
					buf = append(buf, "Rogue Process (High Memory + Growth)"...)
				case ReasonExcessiveSize:
					buf = append(buf, "Excessive Size"...)
				case ReasonRapidGrowth:
					buf = append(buf, "Rapid Growth"...)
				default:
					buf = append(buf, "General Pressure"...)
				}
			}

			buf = append(buf, '\n')

			if file != nil {
				_, _ = file.Write(buf)
			}

			if ev.msgType == 0 {
				_, _ = os.Stdout.Write(buf)
			} else {
				_, _ = os.Stderr.Write(buf)
			}
		}
	}()
}

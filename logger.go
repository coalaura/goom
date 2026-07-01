package main

import (
	"io"
	"strconv"
	"sync"
	"time"
)

type LogReason uint8

const (
	ReasonNone LogReason = iota
	ReasonRogue
	ReasonExcessiveSize
	ReasonRapidGrowth
)

const targetProcessNameWidth = 20

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

var (
	logMu      sync.RWMutex
	logClosed  bool
	loggerDone = make(chan struct{})
)

func sendEvent(ev logEvent) {
	logMu.RLock()
	defer logMu.RUnlock()

	if logClosed {
		return
	}

	select {
	case logChan <- ev:
	default:
	}
}

func sendMsg(msgType int, text string) {
	var event logEvent

	event.msgType = msgType
	event.msgLen = copy(event.message[:], text)

	sendEvent(event)
}

func startLogger(w io.Writer, useColor bool) {
	go func() {
		defer close(loggerDone)

		buf := make([]byte, 0, 512)

		for ev := range logChan {
			buf = buf[:0]

			if useColor {
				buf = append(buf, "\x1b[90m"...)
			}

			buf = time.Now().AppendFormat(buf, "2006-01-02 15:04:05")

			if useColor {
				buf = append(buf, "\x1b[0m"...)
			}

			buf = append(buf, " ["...)

			switch ev.msgType {
			case 0:
				buf = append(buf, "INFO"...)
			case 1:
				if useColor {
					buf = append(buf, "\x1b[33m"...)
				}

				buf = append(buf, "WARN"...)
			case 2:
				if useColor {
					buf = append(buf, "\x1b[31m"...)
				}

				buf = append(buf, "KILL"...)
			default:
				if useColor {
					buf = append(buf, "\x1b[94m"...)
				}

				buf = append(buf, "????"...)
			}

			if useColor {
				buf = append(buf, "\x1b[0m"...)
			}

			buf = append(buf, "] "...)

			if ev.msgLen > 0 {
				buf = append(buf, ev.message[:ev.msgLen]...)
			} else {
				buf = appendUintPadded(buf, uint64(ev.pid), 7)
				buf = append(buf, "/ "...)

				if ev.nameLen > 0 {
					buf = appendProcessName(buf, ev.name[:ev.nameLen])
				} else {
					buf = appendProcessName(buf, []byte("unknown"))
				}

				buf = append(buf, " | Private Commit: "...)
				buf = appendUintPadded(buf, ev.bytes/(1<<20), 5)
				buf = append(buf, " MB | System Commit: "...)
				buf = appendCommitPadded(buf, ev.commit*100, 6)
				buf = append(buf, " | "...)

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

			w.Write(buf)
		}
	}()
}

func stopLogger() {
	logMu.Lock()
	if !logClosed {
		logClosed = true

		close(logChan)
	}
	logMu.Unlock()

	<-loggerDone
}

func appendUintPadded(buf []byte, val uint64, width int) []byte {
	var tmp [20]byte

	b := strconv.AppendUint(tmp[:0], val, 10)
	buf = append(buf, b...)

	for i := len(b); i < width; i++ {
		buf = append(buf, ' ')
	}

	return buf
}

func appendCommitPadded(buf []byte, val float64, width int) []byte {
	var tmp [24]byte

	b := strconv.AppendFloat(tmp[:0], val, 'f', 1, 64)
	buf = append(buf, b...)
	buf = append(buf, '%')

	for i := len(b) + 1; i < width; i++ {
		buf = append(buf, ' ')
	}

	return buf
}

func appendProcessName(buf []byte, name []byte) []byte {
	n := len(name)
	if n > targetProcessNameWidth {
		buf = append(buf, name[:8]...)
		buf = append(buf, "..."...)
		buf = append(buf, name[n-9:]...)
	} else {
		buf = append(buf, name...)

		for i := n; i < targetProcessNameWidth; i++ {
			buf = append(buf, ' ')
		}
	}

	return buf
}

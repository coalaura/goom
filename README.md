# goom

Linux has an OOM killer. When memory runs low, it picks a victim and ends it before the whole system goes down. Windows takes a different approach: it happily hands out memory it doesn't have, slows to a crawl, pages everything to disk and eventually just freezes or crashes; all while assuring every process that yes, there is plenty of memory available.

## What does goom do?

goom runs in the background and watches system commit memory. If available headroom drops below 5% of total commit (or 2 GB, whichever is larger) for 3 consecutive samples, it kills the heaviest user-mode process owned by the current user. It also watches for rogue processes: anything consuming more than 60% of physical RAM and still growing gets flagged immediately and killed on the next confirmed pressure window.

*goom never kills system processes or processes owned by other users.*

## Behavior

- Sampling interval: 200 ms
- Kill threshold: 4 consecutive pressure samples
- Minimum process size to be eligible: 500 MB
- Rogue threshold: >60% of physical RAM and actively growing
- Logs to `goom.log` in the users home directory

## Installation

Download the latest binary from [Releases](https://github.com/coalaura/goom/releases) and run it. No installation required. Run it at startup via Task Scheduler or a shortcut in your startup folder if you want it always active.

## Building

```
go build -o goom.exe .
```

Requires Go 1.22+ and Windows.

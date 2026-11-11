# Tools

## Log Viewer TUI (`pano_tui.py`)

A terminal UI for browsing a Panoptes log by process, which is quicker than reading the raw NDJSON. It pairs each process's creation and termination events and groups every other event (file activity, hook detections) under the process it happened in, so you can open a process and see what it did during its lifetime.

```powershell
pip install textual
python tools/pano_tui.py C:\ProgramData\Panoptes\Logs\pano.log
```

It needs `proc_window.py`, which does the start/end pairing, in the same folder. `--slack <seconds>` widens each process's lifetime by that many seconds either side when matching events to it.

| Screen | Keys |
|--------|------|
| Process list | `Enter` open a process, `/` filter, `s` cycle the sort (tree, start, events, image, PID), `h` hide or show processes that were already running when the log started, `q` quit |
| Process view | `/` filter its events, `t` include its child processes, `r` include events other processes aimed at it (e.g. a remote `PEBWritten` or `RemoteThreadCreated`), `Esc` back |

The default tree sort indents child processes under their parent, and when filtering, the parents of a match stay visible (dimmed) for context. In the process view, the highlighted event is shown in full at the bottom.

See the [service README](../src/service/README.md#logs) for the log format.

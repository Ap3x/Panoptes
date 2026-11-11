#!/usr/bin/env python3
"""
pano_tui.py - browse a Panoptes NDJSON log by process.

    pip install textual
    python pano_tui.py pano.log

Needs proc_window.py in the same folder (it does the start/end pairing).

Process list   Enter open   / filter   s sort   h hide/show pre-existing   q quit
               The default "tree" sort indents child processes under their parent;
               when filtering, parents of a match stay visible (dimmed) for context.
Process view   / filter events   t include child processes
               r include events other processes aimed at this one
               Esc back      (the highlighted event is shown in full at the bottom)
"""
import argparse
import json
from datetime import datetime

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from proc_window import analyze, descendants, fmt

SORTS = ["tree", "start", "events", "image", "pid"]
SKIP = {"Event", "PID", "TID", "Time"}


def duration(p):
    if p.start and p.end:
        return f"{int((p.end - p.start).total_seconds())}s"
    return "running" if p.start else "-"


def summarize(ev):
    """One-line description of an event for the table."""
    e = ev.get("Event", "")
    if "Path" in ev:
        s = ev["Path"] or "(no path)"
        if ev.get("NewPath"):
            s += f"  ->  {ev['NewPath']}"
        if "Bytes" in ev:
            s += f"   [{ev['Bytes']} bytes" + (f", {ev['Writes']} writes]" if "Writes" in ev else "]")
        return s
    if e == "ProcessCreated":
        return f"parent {ev.get('ParentPID')}  {ev.get('CommandLine') or ev.get('Image', '')}"
    if e == "ProcessTerminated":
        return ""
    if "Api" in ev:
        parts = [ev["Api"]]
        if ev.get("Remote"):
            tgt = (ev.get("TargetImage") or "").rsplit("\\", 1)[-1]
            parts.append(f"-> PID {ev.get('TargetProcessId')} {tgt}".rstrip())
        if "BaseAddress" in ev:
            parts.append(ev["BaseAddress"])
        if "OldProtection" in ev:
            parts.append(f"{ev['OldProtection']} -> {ev['NewProtection']}")
        for k in ("Protection", "RegionSize", "ViewSize", "PebOffset", "Size", "ApcRoutine"):
            if k in ev:
                parts.append(f"{k}={ev[k]}")
        return "  ".join(str(x) for x in parts)
    return "  ".join(f"{k}={v}" for k, v in ev.items() if k not in SKIP and not k.startswith("_"))


def clean(ev):
    return {k: v for k, v in ev.items() if not k.startswith("_")}


class ProcessScreen(Screen):
    """One process: its command line and the events inside its lifetime."""

    BINDINGS = [
        Binding("escape", "back", "Back"),
        Binding("slash", "focus_filter", "Filter events"),
        Binding("t", "toggle_tree", "Children"),
        Binding("r", "toggle_remote", "Targeted-by"),
    ]

    def __init__(self, proc, events):
        super().__init__()
        self.proc, self.all_events = proc, events
        self.with_children = self.with_targeted = False
        self.shown = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="info")
        yield Input(placeholder="filter events: type, path, API, address ... (Enter to return to the list)",
                    id="filter")
        yield DataTable(id="events", cursor_type="row", zebra_stripes=True)
        with VerticalScroll(id="detail"):
            yield Static(id="json")
        yield Footer()

    def on_mount(self) -> None:
        p = self.proc
        self.sub_title = f"PID {p.pid}  {p.name or '(started before logging)'}"
        parent = "-"
        if p.ppid is not None:
            parent = str(p.ppid) + (f"  {p.parent.image}" if p.parent and p.parent.image else "")
            if p.creator not in (None, p.ppid):
                parent += f"   (created by PID {p.creator})"
        info = Text()
        for label, value in (
            ("Image    ", p.image or "(started before logging - no ProcessCreated event)"),
            ("Command  ", p.cmdline or "-"),
            ("PID      ", str(p.pid)),
            ("Parent   ", parent),
            ("Lifetime ", f"{fmt(p.start)}  ->  {fmt(p.end)}   ({duration(p)})"),
        ):
            info.append(label, style="bold cyan")
            info.append(value + "\n")
        self.info_text = info
        self.query_one("#events", DataTable).add_columns("Time", "PID", "TID", "Event", "Detail")
        self.refill()
        self.query_one("#events").focus()

    def refill(self) -> None:
        procs = descendants([self.proc]) if self.with_children else [self.proc]
        ids = {id(x) for x in procs}
        needle = self.query_one("#filter", Input).value.lower()
        self.shown = []
        for ev in self.all_events:
            own = ev["_proc"] is not None and id(ev["_proc"]) in ids
            tgt = self.with_targeted and ev["_target"] is not None and id(ev["_target"]) in ids
            if not (own or tgt):
                continue
            if needle and needle not in json.dumps(clean(ev)).lower():
                continue
            self.shown.append(ev)
        self.shown.sort(key=lambda e: (e["_t"] or datetime.min, e["_line"]))

        table = self.query_one("#events", DataTable)
        table.clear()
        for i, ev in enumerate(self.shown):
            foreign = ev.get("PID") != self.proc.pid
            style = "yellow" if foreign else ""
            table.add_row(
                (ev.get("Time") or "")[11:],
                Text(str(ev.get("PID", "")), style=style),
                str(ev.get("TID", "")),
                Text(ev.get("Event", ""), style="bold red" if ev.get("Remote") else style),
                summarize(ev),
                key=str(i),
            )
        status = Text.assemble(
            self.info_text,
            ("Showing  ", "bold cyan"),
            f"{len(self.shown)} events"
            f"   children: {'on' if self.with_children else 'off'} ({len(self.proc.children)} direct)"
            f"   targeted-by: {'on' if self.with_targeted else 'off'}",
        )
        self.query_one("#info", Static).update(status)
        if not self.shown:
            self.query_one("#json", Static).update("No events match.")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        ev = self.shown[int(event.row_key.value)]
        self.query_one("#json", Static).update(
            Text(f"line {ev['_line']}\n" + json.dumps(clean(ev), indent=2)))

    def on_input_changed(self, event: Input.Changed) -> None:
        self.refill()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.query_one("#events").focus()

    def action_back(self) -> None:
        if self.query_one("#filter").has_focus:
            self.query_one("#events").focus()
        else:
            self.app.pop_screen()

    def action_focus_filter(self) -> None:
        self.query_one("#filter").focus()

    def action_toggle_tree(self) -> None:
        self.with_children = not self.with_children
        self.refill()

    def action_toggle_remote(self) -> None:
        self.with_targeted = not self.with_targeted
        self.refill()


class PanoApp(App):
    TITLE = "Panoptes log"
    CSS = """
    #info { height: auto; padding: 0 1; border: round $primary; }
    #filter { margin: 0; }
    DataTable { height: 1fr; }
    #detail { height: 14; border: round $primary; padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("h", "toggle_preexisting", "Pre-existing"),
        Binding("escape", "to_table", "List", show=False),
    ]

    def __init__(self, path, slack=0):
        super().__init__()
        self.path = path
        self.events, self.procs = analyze(path, slack)
        self.sort_by = "tree"
        self.show_pre = True
        self.rows = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Input(placeholder="filter processes: image path, command line or PID (Enter to return to the list)",
                    id="pfilter")
        yield DataTable(id="procs", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#procs", DataTable).add_columns(
            "PID", "PPID", "Start", "End", "Dur", "Events", "Image")
        self.refill()
        self.query_one("#procs").focus()

    def refill(self) -> None:
        needle = self.query_one("#pfilter", Input).value.lower()
        visible = [p for p in self.procs if self.show_pre or p.start is not None]
        matched = [p for p in visible
                   if not needle or needle in f"{p.pid} {p.image} {p.cmdline}".lower()]
        by_start = lambda p: (p.start is None, p.start or datetime.min, p.line)
        if self.sort_by == "tree":
            # oldest first: processes that predate the log, then by start time
            layout = self.tree_layout(
                visible, matched,
                lambda p: (p.start is not None, p.start or datetime.min, p.pid, p.line))
        else:
            keys = {
                "start": by_start,
                "events": lambda p: -p.n_events,
                "image": lambda p: (p.image == "", p.image.lower()),
                "pid": lambda p: p.pid,
            }
            layout = [(p, "", True) for p in sorted(matched, key=keys[self.sort_by])]
        self.rows = rows = [p for p, _, _ in layout]
        table = self.query_one("#procs", DataTable)
        table.clear()
        for i, (p, prefix, hit) in enumerate(layout):
            image = Text(prefix, style="dim")
            image.append(p.image or "(started before logging)",
                         style="" if hit and p.image else "dim")
            table.add_row(
                str(p.pid),
                str(p.ppid) if p.ppid is not None else "-",
                fmt(p.start)[11:] if p.start else "-",
                fmt(p.end)[11:] if p.end else "-",
                duration(p),
                Text(str(p.n_events), justify="right"),
                image,
                key=str(i),
            )
        self.sub_title = (f"{self.path}   {len(matched)}/{len(self.procs)} processes   "
                          f"{len(self.events)} events   sort: {self.sort_by}")

    @staticmethod
    def tree_layout(visible, matched, order):
        """Depth-first (process, indent prefix, is_match) rows.

        Keeps the ancestors of every match so the lineage stays readable, and
        re-homes a process under its nearest shown ancestor when its real
        parent is hidden.
        """
        vis = {id(p) for p in visible}
        keep = {id(p): p for p in matched}
        for p in matched:  # pull in ancestors of each match
            a, hops = p.parent, 0
            while a is not None and hops < 256:
                if id(a) in vis:
                    keep.setdefault(id(a), a)
                a, hops = a.parent, hops + 1
        hits = {id(p) for p in matched}
        kids, roots = {}, []
        for p in keep.values():
            a, hops = p.parent, 0
            while a is not None and id(a) not in keep and hops < 256:
                a, hops = a.parent, hops + 1
            if a is None or a is p:
                roots.append(p)
            else:
                kids.setdefault(id(a), []).append(p)
        out, seen = [], set()

        def walk(p, guides, last, top):
            if id(p) in seen:
                return
            seen.add(id(p))
            prefix = "" if top else guides + ("└─ " if last else "├─ ")
            out.append((p, prefix, id(p) in hits))
            children = sorted(kids.get(id(p), ()), key=order)
            for n, c in enumerate(children):
                walk(c, "" if top else guides + ("   " if last else "│  "),
                     n == len(children) - 1, False)

        for r in sorted(roots, key=order):
            walk(r, "", True, True)
        return out

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pfilter":
            self.refill()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "pfilter":
            self.query_one("#procs").focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "procs" and event.row_key.value is not None:
            self.push_screen(ProcessScreen(self.rows[int(event.row_key.value)], self.events))

    def action_focus_filter(self) -> None:
        self.query_one("#pfilter").focus()

    def action_to_table(self) -> None:
        self.query_one("#procs").focus()

    def action_cycle_sort(self) -> None:
        self.sort_by = SORTS[(SORTS.index(self.sort_by) + 1) % len(SORTS)]
        self.refill()

    def action_toggle_preexisting(self) -> None:
        self.show_pre = not self.show_pre
        self.refill()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Browse a Panoptes log by process.")
    ap.add_argument("log")
    ap.add_argument("--slack", type=float, default=0,
                    help="seconds of tolerance either side of a process lifetime")
    a = ap.parse_args()
    PanoApp(a.log, a.slack).run()

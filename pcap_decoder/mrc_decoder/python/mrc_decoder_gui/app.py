"""Tkinter GUI for mrc_decoder.

Drives the C++ engine in-process via the pybind11 module `mrc_engine` (built from
cpp/bindings). Resolves the SDB from a version string via sdb_fetcher, prompting for
the Artifactory API key at runtime (never stored/logged).
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

try:  # the compiled engine is optional at import time
    import mrc_engine  # type: ignore
except Exception:  # pragma: no cover - engine not built yet
    mrc_engine = None

from sdb_fetcher import fetch_sdb


class App(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=12)
        master.title("MRC Decoder")
        self.grid(sticky="nsew")
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)

        self.pcap_files: List[str] = []
        self.output_dir = tk.StringVar(value=str(Path.cwd()))
        self.sdb_version = tk.StringVar()
        self.arxml_dir = tk.StringVar()
        self.merge = tk.BooleanVar(value=False)
        self._events: "queue.Queue[tuple]" = queue.Queue()

        self._build()
        self.after(100, self._drain_events)

    # -- layout -------------------------------------------------------------
    def _build(self) -> None:
        row = 0
        ttk.Button(self, text="Add PCAP(s)...", command=self._add_pcaps).grid(
            row=row, column=0, sticky="w"
        )
        ttk.Button(self, text="Clear", command=self._clear_pcaps).grid(
            row=row, column=1, sticky="w"
        )
        row += 1

        self.pcap_list = tk.Listbox(self, height=6, width=70)
        self.pcap_list.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=4)
        row += 1

        ttk.Label(self, text="SDB version:").grid(row=row, column=0, sticky="w")
        ttk.Entry(self, textvariable=self.sdb_version, width=20).grid(
            row=row, column=1, sticky="w"
        )
        ttk.Label(self, text="(e.g. 2026.6.1)").grid(row=row, column=2, sticky="w")
        row += 1

        ttk.Label(self, text="or ARXML dir:").grid(row=row, column=0, sticky="w")
        ttk.Entry(self, textvariable=self.arxml_dir, width=40).grid(
            row=row, column=1, sticky="we"
        )
        ttk.Button(self, text="Browse...", command=self._pick_arxml).grid(
            row=row, column=2, sticky="w"
        )
        row += 1

        ttk.Label(self, text="Output dir:").grid(row=row, column=0, sticky="w")
        ttk.Entry(self, textvariable=self.output_dir, width=40).grid(
            row=row, column=1, sticky="we"
        )
        ttk.Button(self, text="Browse...", command=self._pick_output).grid(
            row=row, column=2, sticky="w"
        )
        row += 1

        ttk.Checkbutton(
            self, text="Merge into one MDF (--merge-output)", variable=self.merge
        ).grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1

        self.run_btn = ttk.Button(self, text="Decode", command=self._start)
        self.run_btn.grid(row=row, column=0, sticky="w", pady=6)
        row += 1

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.grid(row=row, column=0, columnspan=3, sticky="we")
        row += 1

        self.status = tk.Text(self, height=8, width=70, state="disabled")
        self.status.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=4)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(row, weight=1)

    # -- actions ------------------------------------------------------------
    def _add_pcaps(self) -> None:
        files = filedialog.askopenfilenames(
            title="Select PCAP files",
            filetypes=[("PCAP", "*.pcap *.pcapng"), ("All", "*.*")],
        )
        for f in files:
            if f not in self.pcap_files:
                self.pcap_files.append(f)
                self.pcap_list.insert(tk.END, f)

    def _clear_pcaps(self) -> None:
        self.pcap_files.clear()
        self.pcap_list.delete(0, tk.END)

    def _pick_output(self) -> None:
        d = filedialog.askdirectory(title="Output directory")
        if d:
            self.output_dir.set(d)

    def _pick_arxml(self) -> None:
        d = filedialog.askdirectory(title="Consolidated ARXML directory")
        if d:
            self.arxml_dir.set(d)

    def _log(self, text: str) -> None:
        self.status.configure(state="normal")
        self.status.insert(tk.END, text + "\n")
        self.status.see(tk.END)
        self.status.configure(state="disabled")

    def _start(self) -> None:
        if not self.pcap_files:
            messagebox.showwarning("MRC Decoder", "Add at least one PCAP file.")
            return
        if mrc_engine is None:
            messagebox.showerror(
                "MRC Decoder",
                "The compiled engine module 'mrc_engine' is not available.\n"
                "Build the C++ project (cmake) and put mrc_engine on PYTHONPATH.",
            )
            return

        api_key: Optional[str] = None
        if self.arxml_dir.get().strip():
            arxml_dir = self.arxml_dir.get().strip()
        else:
            version = self.sdb_version.get().strip()
            if not version:
                messagebox.showwarning(
                    "MRC Decoder", "Enter an SDB version or ARXML dir."
                )
                return
            # Prompt for the API key at runtime (never stored).
            api_key = _prompt_api_key(self)
            if not api_key:
                return
            arxml_dir = None  # resolved in the worker thread

        self.run_btn.configure(state="disabled")
        self.progress.configure(value=0, maximum=len(self.pcap_files))
        threading.Thread(
            target=self._worker,
            args=(arxml_dir, self.sdb_version.get().strip(), api_key),
            daemon=True,
        ).start()

    def _worker(self, arxml_dir, version, api_key) -> None:
        try:
            if arxml_dir is None:
                self._events.put(
                    ("log", f"Resolving SDB {version} from Artifactory...")
                )
                res = fetch_sdb(version, api_key)
                arxml_dir = str(res.arxml_dir)
                self._events.put(
                    (
                        "log",
                        f"ARXML consolidated: {len(res.arxml_files)} files "
                        f"(downloaded {res.zips_downloaded} zip(s), reused {res.zips_reused}).",
                    )
                )

            opts = mrc_engine.EngineOptions()
            opts.sdb_arxml_dir = arxml_dir
            opts.output_dir = self.output_dir.get()
            opts.merge_output = bool(self.merge.get())
            opts.pcap_files = list(self.pcap_files)

            def progress(idx, total, fname, samples):
                self._events.put(("progress", idx, total, fname, samples))

            result = mrc_engine.run(opts, progress)
            for f in result.files:
                if f.ok:
                    self._events.put(
                        ("log", f"OK: {f.output or f.input} ({f.samples} samples)")
                    )
                else:
                    self._events.put(("log", f"FAILED: {f.input} ({f.error})"))
            if result.merged_output:
                self._events.put(("log", f"Merged: {result.merged_output}"))
            self._events.put(("done", None))
        except Exception as exc:  # pragma: no cover
            self._events.put(("log", f"Error: {exc}"))
            self._events.put(("done", None))

    def _drain_events(self) -> None:
        try:
            while True:
                evt = self._events.get_nowait()
                kind = evt[0]
                if kind == "log":
                    self._log(evt[1])
                elif kind == "progress":
                    _, idx, total, fname, samples = evt
                    self.progress.configure(value=idx, maximum=total)
                    self._log(f"[{idx}/{total}] {fname}: {samples} samples")
                elif kind == "done":
                    self.run_btn.configure(state="normal")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)


def _prompt_api_key(parent: tk.Widget) -> Optional[str]:
    """Modal password prompt; the value is not echoed and not stored."""
    dlg = tk.Toplevel(parent)
    dlg.title("Artifactory API key")
    dlg.transient(parent.winfo_toplevel())
    dlg.grab_set()
    ttk.Label(dlg, text="Enter Artifactory API key:").grid(
        row=0, column=0, padx=10, pady=8
    )
    var = tk.StringVar()
    entry = ttk.Entry(dlg, textvariable=var, show="*", width=40)
    entry.grid(row=1, column=0, padx=10)
    entry.focus_set()
    out = {"key": None}

    def ok():
        out["key"] = var.get()
        dlg.destroy()

    ttk.Button(dlg, text="OK", command=ok).grid(row=2, column=0, pady=8)
    dlg.bind("<Return>", lambda _e: ok())
    parent.wait_window(dlg)
    return out["key"] or None


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()

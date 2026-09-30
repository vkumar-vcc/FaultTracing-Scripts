import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

BAUD_RATES = [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
DEFAULT_BAUD = 115200
CHECKED = "\u2611"
UNCHECKED = "\u2610"
LINE_ENDINGS = {
    "CR (\\r)": b"\r",
    "LF (\\n)": b"\n",
    "CRLF (\\r\\n)": b"\r\n",
    "None": b"",
}
DEFAULT_LINE_ENDING = "CR (\\r)"

# node identification keys, matched against the port's first response
NODE_KEYS = (
    ("LPA", "Atmel LP"),
    ("SGA", "DoIP-"),
    ("HIA", "GoForHIA"),
    ("HIB", "GoForHIB"),
    ("HIC", "GoForHIC"),
    ("HPA", "#"),
)

# ----- your original logic, adapted -----


def determine_port_type(port_info):
    for node, key in NODE_KEYS:
        if key in (port_info or ""):
            return node
    return "Unknown"


def get_first_response(com_port, baudrate=DEFAULT_BAUD, timeout=0.6):
    """Probe a port and return its banner; stops as soon as the reply goes quiet."""
    try:
        with serial.Serial(com_port, baudrate=baudrate, timeout=0.05) as ser:
            ser.reset_input_buffer()
            ser.write(b"\r")  # Send Enter
            deadline = time.monotonic() + timeout
            buffer = b""
            while time.monotonic() < deadline and len(buffer) < 200:
                chunk = ser.read(ser.in_waiting or 1)
                if chunk:
                    buffer += chunk
                    deadline = min(deadline, time.monotonic() + 0.15)
            return buffer.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        # Print to console for debugging, return empty to mark as failure in UI
        print(f"Could not read from {com_port}: {e}")
        return ""


def list_uart_ports():
    ports = serial.tools.list_ports.comports()
    uart_ports = []
    for p in ports:
        desc = p.description or ""
        if ("USB" in desc) or ("UART" in desc) or ("Serial" in desc):
            uart_ports.append(p.device)  # e.g. "COM7"
    return sorted(uart_ports)


# ----- serial logging -----


class PortLogger(threading.Thread):
    """Reads one serial port and writes every line prefixed with a timestamp."""

    def __init__(self, port, baudrate, log_path, timestamp_mode, on_event, on_line=None):
        super().__init__(daemon=True)
        self.port = port
        self.baudrate = baudrate
        self.log_path = log_path
        self.timestamp_mode = timestamp_mode  # "absolute" or "relative"
        self.on_event = on_event
        self.on_line = on_line
        self._stop_event = threading.Event()
        self._start_time = None
        self._serial = None
        self._fh = None
        self._io_lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def send(self, data):
        """Write to the already-open port and mirror the command into the log."""
        with self._io_lock:
            if not self._serial or not self._serial.is_open:
                raise IOError("port not open")
            self._serial.write(data)
            if self._fh:
                text = data.decode("utf-8", errors="replace").replace("\r", "\\r")
                text = text.replace("\n", "\\n")
                self._fh.write(f"{self._stamp()} >> {text}\n")
                self._fh.flush()

    def _stamp(self):
        if self.timestamp_mode == "relative":
            return f"[{time.monotonic() - self._start_time:10.3f}]"
        return f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}]"

    def _emit(self, stamp, line):
        self._fh.write(f"{stamp} {line}\n")
        if self.on_line:
            self.on_line(self.port, stamp, line)

    def run(self):
        self._start_time = time.monotonic()
        try:
            with serial.Serial(self.port, baudrate=self.baudrate, timeout=0.5) as ser, open(
                self.log_path, "a", encoding="utf-8", newline=""
            ) as fh:
                self._serial, self._fh = ser, fh
                fh.write(
                    f"# {self.port} @ {self.baudrate} baud - log started "
                    f"{datetime.now().isoformat(timespec='seconds')}\n"
                )
                fh.flush()
                self.on_event(self.port, "started", self.log_path)
                buffer = b""
                while not self._stop_event.is_set():
                    chunk = ser.read(ser.in_waiting or 1)
                    if not chunk:
                        continue
                    buffer += chunk
                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        line = raw.decode("utf-8", errors="replace").rstrip("\r")
                        self._emit(self._stamp(), line)
                    fh.flush()
                if buffer:
                    line = buffer.decode("utf-8", errors="replace").rstrip("\r")
                    self._emit(self._stamp(), line)
                fh.write(
                    f"# log stopped {datetime.now().isoformat(timespec='seconds')}\n"
                )
        except Exception as e:
            self.on_event(self.port, "error", str(e))
            return
        finally:
            self._serial, self._fh = None, None
        self.on_event(self.port, "stopped", self.log_path)


# ----- GUI app -----


class ConsoleView(ttk.Frame):
    """Send/receive console bound to a single COM port; lives in a tab or its own window."""

    def __init__(self, parent, app, port, detached=False):
        super().__init__(parent)
        self.app = app
        self.port = port
        self.detached = detached
        self.line_ending_var = tk.StringVar(value=DEFAULT_LINE_ENDING)
        self.command_var = tk.StringVar()
        self.history = []
        self.history_index = 0

        top = ttk.Frame(self, padding=(4, 6))
        top.pack(side=tk.TOP, fill=tk.X)
        ttk.Label(
            top, text=app.console_label(port), font=("TkDefaultFont", 9, "bold")
        ).pack(side=tk.LEFT)
        ttk.Label(top, text="Line ending:").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Combobox(
            top,
            textvariable=self.line_ending_var,
            values=list(LINE_ENDINGS),
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT)
        ttk.Button(top, text="Close", command=lambda: app.close_console(self)).pack(
            side=tk.RIGHT, padx=(8, 0)
        )
        ttk.Button(
            top,
            text="Attach" if detached else "Detach",
            command=self._toggle_detach,
        ).pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(top, text="Clear", command=self.clear).pack(
            side=tk.RIGHT, padx=(8, 0)
        )
        ttk.Button(top, text="Save Output...", command=self.save).pack(side=tk.RIGHT)

        entry_row = ttk.Frame(self, padding=(4, 0, 4, 6))
        entry_row.pack(side=tk.TOP, fill=tk.X)
        entry = ttk.Entry(entry_row, textvariable=self.command_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<Return>", lambda e: self.send())
        entry.bind("<Up>", self.history_prev)
        entry.bind("<Down>", self.history_next)
        entry.bind("<Control-c>", self.send_interrupt)
        ttk.Button(entry_row, text="Send", command=self.send).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(
            entry_row, text="Ctrl+C", width=8, command=self.send_interrupt
        ).pack(side=tk.LEFT, padx=(4, 0))

        out_frame = ttk.Frame(self)
        out_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self.text = tk.Text(
            out_frame, wrap=tk.NONE, state=tk.DISABLED, font=("Consolas", 9)
        )
        vsb = ttk.Scrollbar(out_frame, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=vsb.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.bind("<Control-c>", self.copy_selection)
        self.text.tag_configure("tx", foreground="#0a58ca")
        self.text.tag_configure("rx", foreground="#111111")
        self.text.tag_configure("err", foreground="red")
        self.text.tag_configure("info", foreground="#666666")

    def _toggle_detach(self):
        if self.detached:
            self.app.attach_console(self)
        else:
            self.app.detach_console(self)

    def write(self, line, tag="rx"):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, line + "\n", tag)
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def dump(self):
        return self.text.get("1.0", "end-1c")

    def restore(self, text):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, text)
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def clear(self):
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)

    def save(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=f"{self.port}_console.log",
            initialdir=self.app.log_dir_var.get(),
            filetypes=[("Log files", "*.log"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.dump())
        except OSError as e:
            messagebox.showerror("UART Verifier", f"Cannot save output:\n{e}")
            return
        self.app.status_var.set(f"Console output saved: {path}")

    def history_prev(self, event):
        if self.history and self.history_index > 0:
            self.history_index -= 1
            self.command_var.set(self.history[self.history_index])
        return "break"

    def history_next(self, event):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.command_var.set(self.history[self.history_index])
        else:
            self.history_index = len(self.history)
            self.command_var.set("")
        return "break"

    def send(self):
        cmd = self.command_var.get()
        self.app.send_to_port(self.port, cmd, self.line_ending_var.get())
        if cmd:
            self.history.append(cmd)
        self.history_index = len(self.history)
        self.command_var.set("")

    def send_interrupt(self, event=None):
        """Send ETX (0x03), the terminal's Ctrl+C interrupt."""
        self.app.send_raw(self.port, b"\x03", "<Ctrl+C>")
        return "break"

    def copy_selection(self, event=None):
        try:
            selection = self.text.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            return "break"
        self.clipboard_clear()
        self.clipboard_append(selection)
        return "break"


class UARTVerifierApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("UART Verifier")
        self.geometry("900x480")
        self.minsize(720, 400)

        self.loggers = {}  # port -> PortLogger
        self.consoles = {}  # port -> ConsoleView
        self.nodes = {}  # port -> node name (LPA, SGA, HIA, ...)
        self.rows = {}  # port -> tree row id
        self._scanning = False
        self.log_dir_var = tk.StringVar(value=os.path.join(os.getcwd(), "uart_logs"))
        self.baud_var = tk.StringVar(value=str(DEFAULT_BAUD))
        self.timestamp_var = tk.StringVar(value="absolute")
        self.autolog_var = tk.BooleanVar(value=True)

        # toolbar
        bar = ttk.Frame(self, padding=8)
        bar.pack(side=tk.TOP, fill=tk.X)
        self.refresh_btn = ttk.Button(bar, text="Refresh", command=self.refresh)
        self.refresh_btn.pack(side=tk.LEFT)
        ttk.Button(bar, text="Copy Results", command=self.copy_results).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Label(bar, text="Baud:").pack(side=tk.LEFT, padx=(16, 4))
        ttk.Combobox(
            bar,
            textvariable=self.baud_var,
            values=[str(b) for b in BAUD_RATES],
            width=8,
            state="readonly",
        ).pack(side=tk.LEFT)

        # logging toolbar
        logbar = ttk.Frame(self, padding=(8, 0, 8, 8))
        logbar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(logbar, text="Start Logging", command=self.start_logging).pack(
            side=tk.LEFT
        )
        ttk.Button(logbar, text="Stop Logging", command=self.stop_logging).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(logbar, text="Open Console(s)", command=self.open_consoles).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Checkbutton(
            logbar, text="Auto-log responding ports", variable=self.autolog_var
        ).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Label(logbar, text="Timestamp:").pack(side=tk.LEFT, padx=(16, 4))
        ttk.Combobox(
            logbar,
            textvariable=self.timestamp_var,
            values=["absolute", "relative"],
            width=10,
            state="readonly",
        ).pack(side=tk.LEFT)
        ttk.Button(logbar, text="Log Folder...", command=self.choose_log_dir).pack(
            side=tk.LEFT, padx=(16, 4)
        )
        ttk.Label(logbar, textvariable=self.log_dir_var).pack(side=tk.LEFT)

        # tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(0, 4))
        ports_tab = ttk.Frame(self.notebook)
        self.notebook.add(ports_tab, text="Ports")

        # table
        cols = ("sel", "port", "node", "status", "logging", "response")
        self.tree = ttk.Treeview(
            ports_tab, columns=cols, show="headings", height=14, selectmode="extended"
        )
        self.tree.heading("sel", text=CHECKED, command=self.toggle_all)
        self.tree.heading("port", text="COM Port")
        self.tree.heading("node", text="Node")
        self.tree.heading("status", text="Status")
        self.tree.heading("logging", text="Logging")
        self.tree.heading("response", text="First Response (trimmed)")

        self.tree.column("sel", width=40, anchor=tk.CENTER, stretch=False)
        self.tree.column("port", width=100, anchor=tk.W)
        self.tree.column("node", width=80, anchor=tk.W)
        self.tree.column("status", width=80, anchor=tk.W)
        self.tree.column("logging", width=80, anchor=tk.W)
        self.tree.column("response", width=420, anchor=tk.W)
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<space>", self.on_tree_space)
        self.tree.bind("<Double-1>", self.on_tree_double_click)

        vsb = ttk.Scrollbar(ports_tab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0), pady=4)
        vsb.pack(side=tk.RIGHT, fill=tk.Y, pady=4)

        # status line
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, anchor=tk.W, padding=(8, 4)).pack(
            side=tk.BOTTOM, fill=tk.X
        )

        # styles for success/fail
        style = ttk.Style(self)
        style.map("Treeview")
        # tag configuration
        self.tree.tag_configure("ok", foreground="green")
        self.tree.tag_configure("fail", foreground="red")

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(50, lambda: self.refresh(first=True))

    # ----- consoles -----

    def open_consoles(self):
        ports = self.selected_ports()
        if not ports:
            messagebox.showinfo(
                "UART Verifier", "Tick the checkbox of one or more ports to open."
            )
            return
        for port in ports:
            self.open_console(port)

    def open_console(self, port, restore_text=None):
        existing = self.consoles.get(port)
        if existing:
            if existing.detached:
                existing.winfo_toplevel().lift()
            else:
                self.notebook.select(existing)
            return existing
        view = ConsoleView(self.notebook, self, port)
        self.consoles[port] = view
        self.notebook.add(view, text=self.console_label(port))
        self.notebook.select(view)
        if restore_text:
            view.restore(restore_text)
        return view

    def console_label(self, port):
        node = self.nodes.get(port)
        return f"{node} ({port})" if node and node != "Unknown" else port

    def detach_console(self, view):
        port, text = view.port, view.dump()
        self.close_console(view)
        win = tk.Toplevel(self)
        win.title(f"UART Console - {self.console_label(port)}")
        win.geometry("760x420")
        detached = ConsoleView(win, self, port, detached=True)
        detached.pack(fill=tk.BOTH, expand=True)
        detached.restore(text)
        self.consoles[port] = detached
        win.protocol("WM_DELETE_WINDOW", lambda: self.close_console(detached))

    def attach_console(self, view):
        port, text = view.port, view.dump()
        self.close_console(view)
        self.open_console(port, restore_text=text)

    def close_console(self, view):
        if self.consoles.get(view.port) is view:
            self.consoles.pop(view.port, None)
        if view.detached:
            view.winfo_toplevel().destroy()
        else:
            self.notebook.forget(view)
            view.destroy()

    def console_line(self, port, stamp, line, tag="rx"):
        view = self.consoles.get(port)
        if view:
            view.write(f"{stamp} {line}", tag)

    def send_to_port(self, port, cmd, line_ending):
        data = cmd.encode("utf-8") + LINE_ENDINGS[line_ending]
        self.send_raw(port, data, cmd)

    def send_raw(self, port, data, label):
        stamp = self._now_stamp()
        self.console_line(port, stamp, f">> {label}", "tx")

        logger = self.loggers.get(port)
        if logger:
            try:
                logger.send(data)
            except Exception as e:
                self.console_line(port, stamp, f"!! {e}", "err")
            return

        threading.Thread(
            target=self._send_once, args=(port, data, self.current_baud()), daemon=True
        ).start()

    def _send_once(self, port, data, baud, read_seconds=1.5):
        """Open the port only for this exchange when no logger owns it."""
        try:
            with serial.Serial(port, baudrate=baud, timeout=0.2) as ser:
                ser.reset_input_buffer()
                ser.write(data)
                deadline = time.monotonic() + read_seconds
                buffer = b""
                while time.monotonic() < deadline:
                    chunk = ser.read(ser.in_waiting or 1)
                    if chunk:
                        buffer += chunk
                        deadline = time.monotonic() + 0.3
                lines = buffer.decode("utf-8", errors="replace").splitlines()
        except Exception as e:
            self.after(0, self.console_line, port, self._now_stamp(), str(e), "err")
            return
        if not lines:
            self.after(
                0, self.console_line, port, self._now_stamp(), "(no response)", "info"
            )
            return
        for line in lines:
            self.after(0, self.console_line, port, self._now_stamp(), line, "rx")

    @staticmethod
    def _now_stamp():
        return f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}]"

    def refresh(self, first=False):
        if self._scanning:
            return
        ports = list_uart_ports()
        self.tree.delete(*self.tree.get_children())
        self.rows = {}

        if not ports:
            self.status_var.set("No eligible COM ports found.")
            if not first:
                messagebox.showwarning("UART Verifier", "No eligible COM ports found.")
            return

        to_probe = []
        for port in ports:
            if port in self.loggers:
                values = (
                    CHECKED,
                    port,
                    self.nodes.get(port, "Unknown"),
                    "OK",
                    "logging",
                    "(busy - logging)",
                )
                tags = ("ok",)
            else:
                values = (UNCHECKED, port, "", "Scanning...", "", "")
                tags = ()
                to_probe.append(port)
            self.rows[port] = self.tree.insert("", tk.END, values=values, tags=tags)

        if not to_probe:
            self.status_var.set("All ports are logging.")
            return

        self._scanning = True
        self.refresh_btn.configure(state=tk.DISABLED)
        self.status_var.set(f"Scanning {len(to_probe)} port(s)...")
        threading.Thread(
            target=self._scan_ports, args=(to_probe, self.current_baud()), daemon=True
        ).start()

    def _scan_ports(self, ports, baud):
        with ThreadPoolExecutor(max_workers=len(ports)) as pool:
            futures = {
                pool.submit(get_first_response, port, baud): port for port in ports
            }
            for future in as_completed(futures):
                self.after(0, self._apply_scan_result, futures[future], future.result())
        self.after(0, self._scan_done)

    def _apply_scan_result(self, port, resp):
        iid = self.rows.get(port)
        if not iid or not self.tree.exists(iid):
            return
        node = determine_port_type(resp)
        self.nodes[port] = node
        if resp:
            values = (CHECKED, port, node, "OK", "", _shorten(resp, 120))
            tags = ("ok",)
        else:
            values = (UNCHECKED, port, node, "Failed", "", "(no response)")
            tags = ("fail",)
        self.tree.item(iid, values=values, tags=tags)

    def _scan_done(self):
        self._scanning = False
        self.refresh_btn.configure(state=tk.NORMAL)
        failed = sum(
            1
            for iid in self.tree.get_children()
            if self.tree.set(iid, "status") == "Failed"
        )
        if failed:
            self.status_var.set(f"{failed} port(s) failed to respond.")
        else:
            self.status_var.set("All ports are responding!")

        if self.autolog_var.get():
            self.start_logging(quiet=True)

    def copy_results(self):
        rows = []
        for iid in self.tree.get_children():
            _, port, node, status, logging_state, resp = self.tree.item(iid, "values")
            rows.append(f"{port}\t{node}\t{status}\t{logging_state}\t{resp}")
        text = "\n".join(rows) if rows else "No results."
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        messagebox.showinfo("UART Verifier", "Results copied to clipboard.")

    # ----- checkbox handling -----

    def _toggle_row(self, iid):
        current = self.tree.set(iid, "sel")
        self.tree.set(iid, "sel", UNCHECKED if current == CHECKED else CHECKED)

    def on_tree_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return None
        if self.tree.identify_column(event.x) != "#1":
            return None
        iid = self.tree.identify_row(event.y)
        if iid:
            self._toggle_row(iid)
        return "break"

    def on_tree_space(self, event):
        for iid in self.tree.selection():
            self._toggle_row(iid)
        return "break"

    def on_tree_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and self.tree.identify_column(event.x) != "#1":
            self.open_console(self.tree.set(iid, "port"))
        return "break"

    def toggle_all(self):
        rows = self.tree.get_children()
        check_all = any(self.tree.set(iid, "sel") == UNCHECKED for iid in rows)
        for iid in rows:
            self.tree.set(iid, "sel", CHECKED if check_all else UNCHECKED)
        self.tree.heading("sel", text=CHECKED if check_all else UNCHECKED)

    # ----- logging control -----

    def current_baud(self):
        try:
            return int(self.baud_var.get())
        except ValueError:
            return DEFAULT_BAUD

    def choose_log_dir(self):
        folder = filedialog.askdirectory(initialdir=self.log_dir_var.get())
        if folder:
            self.log_dir_var.set(folder)

    def selected_ports(self):
        return [
            self.tree.set(iid, "port")
            for iid in self.tree.get_children()
            if self.tree.set(iid, "sel") == CHECKED
        ]

    def start_logging(self, quiet=False):
        ports = [p for p in self.selected_ports() if p not in self.loggers]
        if not ports:
            if not quiet:
                messagebox.showinfo(
                    "UART Verifier", "Tick the checkbox of one or more ports to log."
                )
            return

        log_dir = self.log_dir_var.get()
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError as e:
            messagebox.showerror("UART Verifier", f"Cannot create log folder:\n{e}")
            return

        baud = self.current_baud()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        for port in ports:
            node = self.nodes.get(port, "Unknown")
            path = os.path.join(log_dir, f"{port}_{node}_{stamp}.log")
            logger = PortLogger(
                port,
                baud,
                path,
                self.timestamp_var.get(),
                self.on_logger_event,
                self.on_logger_line,
            )
            self.loggers[port] = logger
            logger.start()
        self.status_var.set(f"Logging {len(ports)} port(s) to {log_dir}")

    def stop_logging(self):
        ports = self.selected_ports() or list(self.loggers)
        stopped = 0
        for port in ports:
            logger = self.loggers.get(port)
            if logger:
                logger.stop()
                stopped += 1
        if stopped:
            self.status_var.set(f"Stopping {stopped} logger(s)...")

    def on_logger_event(self, port, event, detail):
        # called from logger threads
        self.after(0, self._handle_logger_event, port, event, detail)

    def on_logger_line(self, port, stamp, line):
        # called from logger threads
        self.after(0, self.console_line, port, stamp, line, "rx")

    def _handle_logger_event(self, port, event, detail):
        if event in ("stopped", "error"):
            self.loggers.pop(port, None)
        self._set_logging_cell(port, {"started": "logging", "error": "error"}.get(event, ""))
        if event == "error":
            self.status_var.set(f"{port}: {detail}")
            messagebox.showerror("UART Verifier", f"{port} logging failed:\n{detail}")
        elif event == "started":
            self.status_var.set(f"{port} -> {detail}")
        else:
            self.status_var.set(f"{port} log saved: {detail}")

    def _set_logging_cell(self, port, text):
        for iid in self.tree.get_children():
            if self.tree.set(iid, "port") == port:
                self.tree.set(iid, "logging", text)
                return

    def on_close(self):
        loggers = list(self.loggers.values())
        for logger in loggers:
            logger.stop()
        deadline = time.monotonic() + 2
        for logger in loggers:
            logger.join(timeout=max(0, deadline - time.monotonic()))
        self.destroy()


def _shorten(s, n):
    s = s or ""
    return (s[: n - 1] + "…") if len(s) > n else s


if __name__ == "__main__":
    app = UARTVerifierApp()
    app.mainloop()

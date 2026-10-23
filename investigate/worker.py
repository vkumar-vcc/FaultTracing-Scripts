"""Investigation worker: runs queued jobs on this machine, one at a time.

For each job it runs collect.py to gather the VIN's logs, then Copilot CLI with the
``root-cause`` agent, and saves the agent's answer as ``report.md``. A job re-queued with
engineer feedback (``reanalyse`` marker) skips collection and only runs the agent again.

    python investigate/worker.py            # keep polling for jobs
    python investigate/worker.py --once     # process the queue, then exit

The worker uses this machine's access: SMB readout share credentials from the OS
keychain, ``az login`` for the NUC archive, and the Copilot CLI login.
"""

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import jobs  # noqa: E402

AGENT_NAME = "root-cause"
COLLECT_TIMEOUT = int(os.environ.get("INVESTIGATION_COLLECT_TIMEOUT", 60 * 60))
AGENT_TIMEOUT = int(os.environ.get("INVESTIGATION_AGENT_TIMEOUT", 60 * 60))
POLL_SECONDS = 5
# The only shell command the agent may run: the collector launcher (chained commands are denied).
AGENT_SHELL_PERMISSION = r"shell(investigate\collect.ps1:*)"


def copilot_command():
    """The Copilot CLI as an argument list; never a .bat/.cmd shim, so arguments are not re-parsed by cmd."""
    configured = os.environ.get("INVESTIGATION_COPILOT")
    if configured:
        path = Path(configured)
        if path.suffix.lower() == ".js":
            return [shutil.which("node") or "node", str(path)]
        if path.suffix.lower() in (".bat", ".cmd", ".ps1"):
            raise RuntimeError("INVESTIGATION_COPILOT must point to copilot.exe or the npm package's npm-loader.js.")
        return [str(path)]
    executable = shutil.which("copilot.exe") if os.name == "nt" else shutil.which("copilot")
    if executable:
        return [executable]
    loader = Path(os.environ.get("APPDATA", "")) / "npm" / "node_modules" / "@github" / "copilot" / "npm-loader.js"
    node = shutil.which("node")
    if loader.is_file() and node:
        return [node, str(loader)]
    raise RuntimeError(
        "Copilot CLI not found. Install it (winget install GitHub.Copilot) and run `copilot login`, "
        "or set INVESTIGATION_COPILOT to copilot.exe."
    )


def agent_prompt(folder):
    prompt = (
        f"Investigate the vehicle problem in the job folder {folder} . "
        f"Start by reading {folder / 'request.json'} and {folder / 'collected' / 'manifest.md'} , "
        "then follow your method. To collect more data, run only: "
        f'investigate\\collect.ps1 --job "{folder}" [options] . '
    )
    feedback = folder / jobs.FEEDBACK_MARKDOWN
    if feedback.is_file():
        versions = jobs.previous_reports(folder)
        latest = f" Your latest earlier report is {versions[-1][1]} ." if versions else ""
        prompt += (
            f"This is a re-analysis. Engineers reviewed earlier reports and wrote feedback in {feedback} ; "
            f"read it before you start.{latest} "
        )
    return prompt + "Reply with the report only, in the required structure."


def agent_arguments(folder):
    arguments = [
        "-p", agent_prompt(folder),
        "--agent", AGENT_NAME,
        "-C", str(ROOT),
        "--add-dir", str(folder),
        "--allow-tool", AGENT_SHELL_PERMISSION,
        "--deny-tool", "write",
        "--no-ask-user",
        "--disable-builtin-mcps",
        "--silent",
        "--share", str(folder / "agent_session.md"),
    ]
    model = os.environ.get("INVESTIGATION_MODEL")
    if model:
        arguments += ["--model", model]
    return arguments


class JobLog:
    def __init__(self, folder):
        self.path = Path(folder) / "worker.log"

    def __call__(self, message):
        line = f"[{jobs.iso(jobs.utc_now())}] {message}"
        print(line, flush=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def run_logged(command, log_file, timeout, cwd=ROOT):
    with open(log_file, "a", encoding="utf-8") as output:
        return subprocess.run(
            command,
            cwd=cwd,
            stdout=output,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        )


def collect(folder, log):
    jobs.set_status(folder, "collecting", "Collecting readouts and NUC logs for the VIN.")
    log("Collecting logs.")
    result = run_logged(
        [sys.executable, str(HERE / "collect.py"), "--job", str(folder)],
        folder / "collect.log",
        COLLECT_TIMEOUT,
    )
    log(f"Collector finished with exit code {result.returncode}.")
    if not (folder / "collected" / "manifest.md").is_file():
        raise RuntimeError("The collector produced no manifest; see collect.log.")
    return result.returncode


def analyse(folder, log):
    jobs.set_status(folder, "analysing", "The root-cause agent is analysing the logs.")
    command = copilot_command() + agent_arguments(folder)
    log("Starting the root-cause agent.")
    with open(folder / "agent.stderr.log", "a", encoding="utf-8") as errors:
        result = subprocess.run(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=errors,
            stdin=subprocess.DEVNULL,
            timeout=AGENT_TIMEOUT,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    report = (result.stdout or "").strip()
    log(f"Agent finished with exit code {result.returncode} ({len(report):,} characters).")
    if result.returncode != 0 or not report:
        (folder / "agent.stdout.log").write_text(result.stdout or "", encoding="utf-8")
        raise RuntimeError(f"The agent failed (exit code {result.returncode}); see agent.stderr.log.")
    start = report.find("# Root-cause report")
    (folder / "report.md").write_text((report[start:] if start > 0 else report) + "\n", encoding="utf-8")


def process(folder):
    folder = Path(folder)
    log = JobLog(folder)
    try:
        marker = folder / jobs.REANALYSE_MARKER
        reanalysis = marker.is_file() and (folder / "collected" / "manifest.md").is_file()
        if reanalysis:
            collect_code = 0
            log("Re-analysing with engineer feedback; keeping the collected logs.")
        else:
            collect_code = collect(folder, log)
        analyse(folder, log)
        marker.unlink(missing_ok=True)
        message = "Report updated with your feedback." if reanalysis else "Report ready."
        if collect_code != 0:
            message += " Log collection failed for every source; the report explains what is missing."
        jobs.set_status(folder, "done", message)
        log(message)
    except subprocess.TimeoutExpired as error:
        jobs.set_status(folder, "failed", "Timed out. Raise INVESTIGATION_COLLECT_TIMEOUT or INVESTIGATION_AGENT_TIMEOUT.")
        log(f"Timed out: {error.cmd[0]} exceeded its time limit.")
    except Exception as error:
        jobs.set_status(folder, "failed", str(error))
        log(f"Failed: {error}\n{traceback.format_exc()}")


def heartbeat_loop(root, state, stop):
    while not stop.wait(30):
        jobs.write_heartbeat(root, state=state)


def keep_awake(active):
    """Stop Windows from sleeping while a job runs; a sleeping host stalls downloads and the agent."""
    if os.name != "nt":
        return
    import ctypes

    es_continuous, es_system_required = 0x80000000, 0x00000001
    ctypes.windll.kernel32.SetThreadExecutionState(es_continuous | (es_system_required if active else 0))


def run_queue(root=None):
    processed = 0
    while True:
        folder = jobs.claim_next_job(root)
        if folder is None:
            return processed
        state = f"working on {folder.name}"
        jobs.write_heartbeat(root, state=state)
        stop = threading.Event()
        beat = threading.Thread(target=heartbeat_loop, args=(root, state, stop), daemon=True)
        beat.start()
        keep_awake(True)
        try:
            process(folder)
        finally:
            keep_awake(False)
            stop.set()
            beat.join()
        processed += 1
        jobs.write_heartbeat(root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--once", action="store_true", help="Process queued jobs, then exit")
    args = parser.parse_args(argv)

    root = jobs.jobs_root()
    copilot_command()  # fail fast when the CLI is missing
    for folder in jobs.requeue_interrupted_jobs(root):
        print(f"Requeued interrupted job {folder.name}", flush=True)
    print(f"Investigation worker watching {root}", flush=True)
    while True:
        jobs.write_heartbeat(root)
        run_queue(root)
        if args.once:
            return 0
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())

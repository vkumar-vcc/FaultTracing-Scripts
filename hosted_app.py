"""Shared front door and navigation for independently hosted Streamlit tools."""

from html import escape
from pathlib import Path
import runpy
import sys

import streamlit as st


ROOT = Path(__file__).resolve().parent
TOOLS = {
    "readout": ("Vehicle readout analysis", ROOT / "decoder" / "decoder.py"),
    "pcap": ("PCAP decoder (WSL)", ROOT / "pcap_decoder" / "streamlit_app.py"),
    "someip": ("SOME/IP communication analyzer", ROOT / "someip_comm_analyzer" / "streamlit_app.py"),
    "can": ("CAN signal viewer", ROOT / "can_decoder" / "signal_viewer.py"),
}


def navigation_html() -> str:
    links = ['<a href="/" target="_self">Home</a>']
    links.extend(
        f'<a href="/{key}/" target="_self">{escape(title)}</a>'
        for key, (title, _) in TOOLS.items()
    )
    return '<nav aria-label="Fault tracing tools">' + " | ".join(links) + "</nav>"


def main() -> None:
    tool = sys.argv[1] if len(sys.argv) > 1 else None
    if tool is not None and tool not in TOOLS:
        st.error(f"Unknown hosted tool: {tool}")
        st.stop()

    st.set_page_config(page_title="Fault tracing tools", layout="wide")
    st.html(navigation_html())
    if tool is None:
        st.title("Fault tracing tools")
        st.write("Choose a tool above. All tools use this address; PCAP decoding runs in WSL.")
        for key, (title, _) in TOOLS.items():
            st.html(f'<p><a href="/{key}/" target="_self">{escape(title)}</a></p>')
        return

    _, script = TOOLS[tool]
    # Preserve standalone imports and CAN's optional Parquet command-line argument.
    if str(script.parent) not in sys.path:
        sys.path.insert(0, str(script.parent))
    original_argv = sys.argv
    sys.argv = [str(script), *original_argv[2:]]
    try:
        runpy.run_path(str(script), run_name="__main__")
    finally:
        # Streamlit reuses argv on widget reruns, including after st.stop().
        sys.argv = original_argv


if __name__ == "__main__":
    main()

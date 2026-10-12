# PCAP decoder — self-contained image (builds the native engine; no host WSL needed).
# Ubuntu 22.04 matches the engine's cp310 / glibc 2.35 toolchain.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHERUSAGESTATS=false

# Build + runtime deps: Python 3.10, C++ toolchain, pybind11, libpcap, pugixml, zstd.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.10 python3.10-dev python3-pip \
        build-essential cmake git \
        pybind11-dev libpcap-dev libpugixml-dev \
        zstd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Python UI + decoder dependencies (protobuf stays pinned at 3.20.3 via the frozen file).
RUN python3 -m pip install --upgrade pip \
    && python3 -m pip install -r requirements-ui.txt

# Build the pybind11 engine module into mrc_decoder/build (loaded at runtime).
RUN cmake -S mrc_decoder -B mrc_decoder/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build mrc_decoder/build --target mrc_engine -j"$(nproc)"

EXPOSE 8501

# Captures are provided via the browser Upload mode; outputs download from the UI.
CMD ["python3", "-m", "streamlit", "run", "streamlit_app.py", \
     "--server.address=0.0.0.0", "--server.port=8501"]

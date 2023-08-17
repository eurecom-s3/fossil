# Use it with --network="host"
FROM debian:12-slim

# Install dependencies
RUN apt-get -qq update && \
    apt-get -qq install -y --no-install-recommends \
    ca-certificates \
    g++=4:12.2.0-3 \
    gdb=13.1-3 \
    gdb-multiarch=13.1-3 \
    make=4.3-4.1 \
    git=1:2.39.2-1.1 \
    python3=3.11.2-1+b1 \
    python3-pip=23.0.1+dfsg-1 \
    python3-dev=3.11.2-1+b1 \
    python3-venv=3.11.2-1+b1 \
    cmake=3.25.1-1 \
    libboost-dev=1.74.0.3 \
    libboost-program-options-dev=1.74.0.3 \
    libboost-iostreams-dev=1.74.0.3 \
    libboost-filesystem-dev=1.74.0.3 \
    libboost-thread-dev=1.74.0.3 \
    libboost-test-dev=1.74.0.3 \
    libsnappy-dev=1.1.9-3 \
    python3-graph-tool=2.45+ds-10 \
    unzip=6.0-28 \
    wget=1.21.3-1+b2 \
    less=590-2 \
    openjdk-17-jdk=17.0.8+7-1~deb12u1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone Fossil
RUN git clone https://github.com/eurecom-s3/fossil.git /fossil
WORKDIR /fossil

# Install python dependencies and build Cython code
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip3 install -r requirements.txt && \
    python3 setup.py build_ext --inplace && \
    echo "/usr/lib/python3/dist-packages" > `find venv -name site-packages`/dist-packages.pth && \
    deactivate

# Install Ghidra
RUN cd ghidra && \
    wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip && \
    unzip ghidra_10.3.2_PUBLIC_20230711.zip && \
    rm ghidra_10.3.2_PUBLIC_20230711.zip && \
    mv ghidra_10.3.2_PUBLIC ghidra && \
    sed -i s/MAXMEM=2G/MAXMEM=8G/g ghidra/support/analyzeHeadless

# Set environment variables
ENV GHIDRA_PATH="/fossil/ghidra/ghidra"
ENV PATH="/fossil/venv/bin:$PATH"
ENV PYTHONUNBUFFERED="1"

# Volume containing dumps and results
VOLUME /data

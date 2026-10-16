# BinShield Ghidra Decompiler Image
# Multi-stage build for a lean production image with Ghidra headless analysis.

FROM ubuntu:26.04 AS base

ARG GHIDRA_VERSION=11.3
ARG GHIDRA_DATE=20250205
ARG GHIDRA_SHA256=a80960e4e8b1533ea01ed04209d297e15b1e35afaa79559c28fee39e4b0aaa83

ENV DEBIAN_FRONTEND=noninteractive

# Install Java 17 and required utilities in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk-headless \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and verify Ghidra
WORKDIR /opt
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O ghidra.zip \
    && echo "${GHIDRA_SHA256}  ghidra.zip" | sha256sum -c - \
    && unzip -q ghidra.zip \
    && mv ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm ghidra.zip

# -------------------------------------------------------------------
# Production stage -- drop wget/unzip, keep only the runtime
# -------------------------------------------------------------------
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV GHIDRA_INSTALL_DIR=/opt/ghidra

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Copy Ghidra from builder stage
COPY --from=base /opt/ghidra /opt/ghidra

# Copy analysis scripts
COPY scripts/decompile.py /opt/binshield/scripts/decompile.py
COPY scripts/entrypoint.sh /opt/binshield/scripts/entrypoint.sh
RUN chmod +x /opt/binshield/scripts/entrypoint.sh

# Create working directories
RUN mkdir -p /work/input /work/output /work/projects

ENTRYPOINT ["/opt/binshield/scripts/entrypoint.sh"]

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and kernel development packages
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    linux-headers-generic \
    linux-source \
    sparse \
    coccinelle \
    git \
    wget \
    curl \
    kmod \
    bc \
    flex \
    bison \
    libssl-dev \
    libelf-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up a generic kernel build environment
# We'll use the installed generic headers
RUN mkdir -p /lib/modules/generic && \
    GENERIC_KERNEL=$(ls -d /usr/src/linux-headers-*-generic | head -1) && \
    ln -sf $GENERIC_KERNEL /lib/modules/generic/build && \
    echo "Kernel build directory: /lib/modules/generic/build -> $GENERIC_KERNEL" && \
    ls -la /lib/modules/generic/build/Makefile

# Create working directory
WORKDIR /workspace

# Set up kernel build environment variables
ENV ARCH=x86_64
ENV KDIR=/lib/modules/generic/build

CMD ["/bin/bash"]
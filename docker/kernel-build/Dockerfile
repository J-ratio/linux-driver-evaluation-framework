FROM ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build tools and kernel headers
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    make \
    linux-headers-generic \
    sparse \
    coccinelle \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /workspace

# Set up kernel build environment variables
ENV ARCH=x86_64

CMD ["/bin/bash"]
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Multi-stage Dockerfile for Key Protection Module
FROM golang:1.24-bookworm AS builder

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install build dependencies
RUN apt-get update && apt-get install -y \
    curl \
    tar \
    g++ \
    libssl-dev \
    pkg-config \
    clang \
    libclang-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install CMake 3.28.3 from pre-compiled binaries
RUN curl -sSL https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3-linux-x86_64.tar.gz -o cmake.tar.gz \
    && tar -zxvf cmake.tar.gz -C /opt/ \
    && rm cmake.tar.gz
ENV PATH="/opt/cmake-3.28.3-linux-x86_64/bin:${PATH}"

# Install cbindgen and bindgen-cli
RUN cargo install cbindgen bindgen-cli

WORKDIR /app

# Copy the entire project including submodules
COPY . .

# Generate FFI headers
RUN ./generate_ffi_headers.sh

# Build Rust workspace in release mode
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --workspace

# Build the Go service
# Ensure CGO is enabled and points to the Rust library
ENV CGO_ENABLED=1
ENV CGO_LDFLAGS="-L/app/target/release"
# Add ldflags for optimization and lazy loading of shared libs, matching go-tpm-tools
RUN go build -v -o /app/agent \
    -ldflags="-extldflags=-Wl,-z,lazy -s -w" \
    ./cmd/agent

# Final runtime image
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/agent /usr/local/bin/agent

ENTRYPOINT ["/usr/local/bin/agent"]

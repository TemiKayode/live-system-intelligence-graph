# ─── Stage 1: Build eBPF C object ─────────────────────────────────────────────
FROM ubuntu:24.04 AS bpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-18 llvm-18 libbpf-dev linux-headers-generic \
    && ln -sf /usr/bin/clang-18 /usr/bin/clang \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY ebpf/uprobe.bpf.c .

# Generate vmlinux.h for the current kernel ABI
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || \
    apt-get install -y --no-install-recommends linux-tools-generic && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

RUN clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf -I. \
    -c uprobe.bpf.c -o uprobe.bpf.o

# ─── Stage 2: Build Go binary ─────────────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o runtime-agent .

# ─── Stage 3: Minimal runtime image ──────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    llvm \
    binutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/lsig

COPY --from=bpf-builder /build/uprobe.bpf.o ./
COPY --from=go-builder  /src/runtime-agent  ./

# Non-root user — note: still needs CAP_SYS_PTRACE granted at pod level
RUN useradd -r -s /bin/false lsig
USER lsig

EXPOSE 9091

ENTRYPOINT ["/opt/lsig/runtime-agent"]
CMD ["--bpf-object", "/opt/lsig/uprobe.bpf.o", \
     "--kafka-brokers", "kafka:9092", \
     "--kafka-topic", "runtime_calls", \
     "--metrics-addr", ":9091"]

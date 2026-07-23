CC ?= gcc
CFLAGS ?= -O2 -Wall
NVCC ?= nvcc

all: cpu_crypto_bench swiotlb_copy_bench pcie_bench

cpu_crypto_bench: cpu_crypto_bench.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

swiotlb_copy_bench: swiotlb_copy_bench.c
	$(CC) $(CFLAGS) -o $@ $<

pcie_bench: pcie_bench.cu
	$(NVCC) -O2 -o $@ $<

clean:
	rm -f cpu_crypto_bench swiotlb_copy_bench pcie_bench

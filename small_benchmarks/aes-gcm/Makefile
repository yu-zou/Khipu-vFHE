# Makefile for AES-256-GCM / GMAC-256 throughput benchmark

CXX := g++
CXXFLAGS := -O3 -march=native -std=c++17 -Wall -Wextra
LDFLAGS := -lssl -lcrypto

TARGET := bench

.PHONY: all clean run

all: $(TARGET)

$(TARGET): bench.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) report.md *.csv

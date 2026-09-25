CXX ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -pedantic
NVCC ?= nvcc
NVCCFLAGS ?= -O3 -std=c++17
CUDA_ARCH ?= sm_80

.PHONY: all test clean

all: salsa_search

salsa_search: salsa_search.cu cli.hpp salsa.hpp
	$(NVCC) $(NVCCFLAGS) -arch=$(CUDA_ARCH) salsa_search.cu -o $@

test_host: test_host.cpp cli.hpp salsa.hpp
	$(CXX) $(CXXFLAGS) test_host.cpp -o $@

test: test_host
	./test_host

clean:
	rm -f salsa_search test_host

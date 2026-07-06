PYTHON3   ?= python3
FANFP      = fanfp.py
TEST_PCAP  = test/test-protos.pcap
TEST_EXP   = test/test-protos.out.json

.PHONY: help test

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  test   Run fanfp.py against $(TEST_PCAP) and verify fingerprints match $(TEST_EXP)"

test:
	@$(PYTHON3) test/check-protos.py $(FANFP) $(TEST_PCAP) $(TEST_EXP)
	@$(PYTHON3) test/tcp-reassembly.py
	@$(PYTHON3) test/ipv6-extension-headers.py
	@$(PYTHON3) test/capture-linktypes.py

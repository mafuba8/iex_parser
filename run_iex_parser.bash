#!/bin/bash
# Simple bash script to show how to convert a compressed PCAP file from IEX HIST into the format needed by
# the IEX HIST parser.
# 
# https://github.com/mafuba8/iex_parser
# 

# The pcap.gz file from the IEX HIST.
INPUTFILE=example/data_feeds_20180127_20180127_IEXTP1_DEEP1.0.pcap.gz
# The parser will create files named 'output-<message-type>.csv' within this directory.
OUTPUTDIR=output/DEEP-20180127
mkdir -p "$OUTPUTDIR"

# Since the raw files are pretty big, we can pipe them directly into the parser.
gunzip -d -c "$INPUTFILE" | tcpdump -r - -w - -s 0 | python3 iex_parser.py /dev/stdin "$OUTPUTDIR"

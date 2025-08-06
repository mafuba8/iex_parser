# IEX Data Parser
This is a Python-based Parser for converting Market Data from the 
[IEX HIST](https://iextrading.com/trading/market-data/) into CSV files. Data from IEX is 
presented as PCAP files, which is a raw dump of network packets in the IEX-TP protocol.

While other Python Parsers suffer in performance due to their reliance on packet capture 
modules like `scapy`, this parser works directly at the byte-level by reading the 
network packets according to the 
[IEX-TP specification](https://www.iexexchange.io/resources/trading/documents#specifications).

It provides the following benefits:
- Higher performance than other Python-based Parsers.
- Only depends on native Python modules.
- Support for all message types in the DEEP1.0 specification.


## How to Use
The parser needs its input in raw PCAP format, so we need to unzip and apply `tcpdump` to those files:
```bash
mkdir output_directory

# Extract pcap.gz into .raw file and use that one.
$ gunzip -d -c example/data_feeds_20180127_20180127_IEXTP1_DEEP1.0.pcap.gz | \
    tcpdump -r - -w - -s 0 > example/data_feeds_20180127_20180127_IEXTP1_DEEP1.0.raw
$ python3 iex_parser.py example/data_feeds_20180127_20180127_IEXTP1_DEEP1.0.raw output_directory

# Since raw files are pretty big, is is better to pipe them:
gunzip -d -c example/data_feeds_20180127_20180127_IEXTP1_DEEP1.0.pcap.gz | \
    tcpdump -r - -w - -s 0 | python3 iex_parser.py /dev/stdin output_directory
```


## Output
For each message type, the parser will create one file `output-<message_type>.csv` within the
output directory:
- Administrative Messages
  - System Event Messages (S): `output-S.csv`
  - Security Directory Messages (D): `output-D.csv`
  - Trading Status Message (H): `output-H.csv`
  - Retail Liquidity Indicator Message (I): `output-I.csv`
  - Operational Halt Status Message (O): `output-O.csv`
  - Short Sale Price Test Status Message (P): `output-P.csv`
  - Security Event Message (E): `output-E.csv`
- Trading Messages
  - Price Level Update - Buy (8): `output-8.csv`
  - Price Level Update - Sell (5): `output-5.csv`
  - Trade Report Message (T): `output-T.csv`
  - Official Price Message (X): `output-X.csv`
  - Trade Break Message (B): `output-B.csv`
- Auction Message Formats
  - Auction Information Message (A): `output-A.csv`

### Timestamps
For analyzing IEX data, three timestamps might be interesting:
- **Packet Capture Time:** Timestamp on the PCAP header.
- **Send Time:** Timestamp on the IEX-TP packet header.
- **Raw Time:** Timestamp on the message header.

We always have `Packet Capture Time <= Send Time <= Raw Time`, so we record the offset of Send Time and Raw Time
to the Packet Capture time. So the first three columns in each file are the following:
- Packet Capture Time
  - in nanoseconds since POSIX (Epoch) time UTC.
- Send Time Offset
  - `Send Time - Packet Capture Time`
  - in nanoseconds 
- Raw Time Offset
  - `Raw Time - Packet Capture Time`
  - in nanoseconds

So we have:
```
Send Time = Packet Capture Time + Send Time Offset
Raw Time  = Packet Capture Time + Raw Time Offset
```

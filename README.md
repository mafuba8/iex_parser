# IEX Data Parser
This is a Python-based Parser for converting Market Data from the 
[IEX HIST](https://iextrading.com/trading/market-data/) into CSV files. Data from IEX is provided through
PCAP-NG files, which are raw dumps of network packets in the IEX-TP protocol.

This parser work directly at the byte-level by reading the network packets according to the 
[IEX-TP specification](https://www.iexexchange.io/resources/trading/documents#specifications).

It provides the following benefits:
- Higher performance than other Python-based Parsers.
- Only depends on native Python modules.
- Support for all message types in the DEEP1.0 and TOPS1.6 specification.


## How to Use
The parser takes its input in gzipped PCAP-NG format (which should be the format as presented on the IEX page).

A single file can be parsed with the `iex_parser.py` script:
```bash
$ python3 iex_parser.py <input_file> <output_dir>
```

There is also a script for processing files in parallel. It moves all completed files into a subfolder `DONE`
within the input directory:
```bash
$ python3 batch_parse.py <input_dir> <output_directory>
```

To use the parser within a Python script, create a `Decoder` with the right encoding and with it an `IEXFileParser`
object:
```python
import iex_parser

decoder = iex_parser.Decoder('DEEP_1_0')
parser = iex_parser.IEXFileParser(FILE_INPUT, DIR_OUTPUT, decoder)
parser.parse()
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
  - Price Level Update - Buy (8): `output-8.csv` (DEEP only)
  - Price Level Update - Sell (5): `output-5.csv` (DEEP only)
  - Quote Update Message (Q): `output-Q.csv` (TOPS only)
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

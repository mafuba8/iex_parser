# This file contains functions to decode IEX messages in the DEEP1.0 format.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import decoders.iex_messages as iex_messages

#############################
### Message Type Definitions
#############################
# List of message type for messages in DEEP format.
MESSAGE_TYPES = ['S', 'D', 'H', 'I', 'O', 'P', 'E', '8', '5', 'T', 'X', 'B', 'A']
MESSAGE_TYPE_NAMES = {
    # Administrative Messages
    'S': "System Event",
    'D': "Security Directory",
    'H': "Trading Status",
    'I': "Retail Liquidity Indicator",
    'O': "Operational Halt Status",
    'P': "Short Sale Price Test Status",
    'E': "Security Event",
    # Trading Message Formats
    '8': "Price Level Update - Buy",
    '5': "Price Level Update - Sell",
    'T': "Trade Report",
    'X': "Official Price",
    'B': "Trade Break",
    # Auction Message Formats
    'A': "Auction Information",
}

# Corresponding CSV headers.
CSV_HEADERS = {
    # Administrative Messages
    'S': 'Tick Type,System Event',
    'D': 'Tick Type,Symbol,Round Lot Size,Adjusted POC Price,LULD Tier,Security Directory Flags',
    'H': 'Tick Type,Symbol,Trading Status,Reason',
    'I': 'Tick Type,Symbol,Retail Liquidity Indicator',
    'O': 'Tick Type,Symbol,Operational Halt Status',
    'P': 'Tick Type,Symbol,Short Sale Price Test Status,Detail',
    'E': 'Tick Type,Symbol,Security Event',
    # Trading Message Formats
    'T': 'Tick Type,Symbol,Size,Price,Trade ID,Sale Condition',
    '8': 'Tick Type,Symbol,Price,Size,Record Type,Flag,ASK',
    '5': 'Tick Type,Symbol,Price,Size,Record Type,Flag,ASK',
    'X': 'Tick Type,Symbol,Official Price,Price Type',
    'B': 'Tick Type,Symbol,Size,Price,Trade ID,Sale Condition',
    # Auction Message Formats
    'A': 'Tick Type,Auction Type,Symbol,Paired Shares,Reference Price,Indicative Clearing Price,'
         'Imbalance Shares,Imbalance Side,Extension Number,Scheduled Auction Time,Auction Book Clearing Price,'
         'Collar Reference Price,Lower Auction Collar,Upper Auction Collar',
}


#############################
### Decoder function for DEEP
#############################
def decode(message_payload: bytes) -> iex_messages.Message:
    """Parses the given DEEP1.0 message payload by reading the message type byte from it.

    Returns an object of the corresponding message class.
    """
    # Read the message type byte.
    message_type = chr(message_payload[0])
    match message_type:
        # Administrative Message Formats
        case 'S':  # System Event Message
            return iex_messages.SystemEvent(message_payload)
        case 'D':  # Security Directory Message
            return iex_messages.SecurityDirectory(message_payload)
        case 'H':  # Trading Status Message
            return iex_messages.TradingStatus(message_payload)
        case 'I':  # Retail Liquidity Indicator Message
            return iex_messages.RetailLiquidityIndictor(message_payload)
        case 'O':  # Operational Halt Status Message
            return iex_messages.OperationalHaltStatus(message_payload)
        case 'P':  # Short Sale Price Test Status Message
            return iex_messages.ShortSalePriceTestStatus(message_payload)
        case 'E':  # Security Event Message
            return iex_messages.SecurityEvent(message_payload)
        # Trading Message Formats
        case '8':  # Price Level Update Message (Buy)
            return iex_messages.PriceLevelUpdate(message_payload)
        case '5':  # Price Lecel Update Message (Sell)
            return iex_messages.PriceLevelUpdate(message_payload)
        case 'T':  # Trade Report Message
            return iex_messages.TradeReport(message_payload)
        case 'X':  # Official Price Message
            return iex_messages.OfficialPrice(message_payload)
        case 'B':  # Trade Break Message
            return iex_messages.TradeBreak(message_payload)
        # Auction Message Formats
        case 'A':  # Auction Information Message
            return iex_messages.AuctionInformation(message_payload)

        case _:
            raise Exception('Unknown DEEP1.0 message type.')

# This file contains functions to decode IEX messages in the TOPS1.6 format.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import decoders.iex_messages as iex_messages

# List of Message classes used in the DEEP1.0 format.
message_classes = {
    # Administrative Messages
    'S': iex_messages.SystemEvent,
    'D': iex_messages.SecurityDirectory,
    'H': iex_messages.TradingStatus,
    'I': iex_messages.RetailLiquidityIndictor,
    'O': iex_messages.OperationalHaltStatus,
    'P': iex_messages.ShortSalePriceTestStatus,
    # Trading Messages
    'Q': iex_messages.QuoteUpdate,
    'T': iex_messages.TradeReport,
    'X': iex_messages.OfficialPrice,
    'B': iex_messages.TradeBreak,
    # Auction Messages
    'A': iex_messages.AuctionInformation
}

#############################
### Message Type Definitions
#############################
# List of message type for messages in TOPS format.
MESSAGE_TYPES = [message_type for message_type in message_classes]
MESSAGE_TYPE_NAMES = {message_type: message_classes[message_type].message_type_name
                      for message_type in message_classes}

# Corresponding CSV headers.
CSV_HEADERS = {message_type: message_classes[message_type].csv_header
               for message_type in message_classes}


#############################
### Decoder function for DEEP
#############################
def decode(message_payload: bytes) -> iex_messages.Message:
    """Parses the given TOPS1.6 message payload by reading the message type byte from it.

    Returns an object of the corresponding message class.
    """
    # Read the message type byte.
    message_type = chr(message_payload[0])
    if message_type in message_classes:
        # Return an instance of the message class.
        return message_classes[message_type](message_payload)
    else:
        raise Exception(f'Unknown TOPS1.6 message type: "{message_type}".')

# This file contains functions to decode IEX messages in the DEEP1.0 format.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import struct

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
### Decoder Functions
#############################
def _convert_sale_condition_flags(sale_condition_flags_int: int) -> str:
    """Parses the sale condition byte into a string. Returns a string with all the sale conditions
    separated by a pipe '|'.
    """
    assert sale_condition_flags_int in range(255), "Sale condition flag must be 1 byte."

    # Bitwise operations to figure out the flags.
    sale_conditions = []
    if sale_condition_flags_int & 0x80:
        sale_conditions.append('INTERMARKET_SWEEP')
    if sale_condition_flags_int & 0x40:
        sale_conditions.append('EXTENDED_HOURS')
    else:
        sale_conditions.append('REGULAR_HOURS')
    if sale_condition_flags_int & 0x20:
        sale_conditions.append('ODD_LOT')
    if sale_condition_flags_int & 0x10:
        sale_conditions.append('TRADE_THROUGH_EXEMPT')
    if sale_condition_flags_int & 0x08:
        sale_conditions.append('SINGLE_PRICE_CROSS')

    # Combine all flags into a single field, separated by '|'.
    return '|'.join(sale_conditions)


def decode_system_event_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a System Event Message (message type 'S').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 10, "System Event Message payload size should be 10 bytes."

    # Extract data from the payload.
    system_event_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]

    # Determine system event.
    match chr(system_event_int):
        case 'O':  # Start of Messages
            system_event_string = 'MESSAGES_START'
        case 'S':  # Start of System Hours
            system_event_string = 'SYSTEM_HOURS_START'
        case 'R':  # Start of Regular Market Hours
            system_event_string = 'REGULAR_MARKET_START'
        case 'M':  # End of Regular Market Hours
            system_event_string = 'REGULAR_MARKET_END'
        case 'E':  # End of System Hours
            system_event_string = 'SYSTEM_HOURS_END'
        case 'C':  # End of Messages
            system_event_string = 'MESSAGES_END'
        case _:
            raise Exception('Invalid System Event Message flag')

    # Create message string.
    message_string = f'S,{system_event_string}'
    return timestamp_raw, message_string


def decode_security_directory_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Security Directory Message (message type 'D').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 31, "Security Directory Message payload size should be 31 bytes."

    # Extract data from the payload.
    sd_flag_byte = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    round_lot_size = struct.unpack('<I', message_payload[18:22])[0]
    adjusted_poc_price_raw = struct.unpack('<q', message_payload[22:30])[0]
    luld_tier_int = message_payload[30]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    adjusted_poc_price = round(adjusted_poc_price_raw * 1e-4, 2)

    # Determine security directory flags.
    sd_flags = []
    if sd_flag_byte & 0x80:  # Symbol is a test security.
        sd_flags.append('TEST_SECURITY')
    if sd_flag_byte & 0x40:  # Symbol is a when issued security.
        sd_flags.append('WHEN_ISSUED')
    if sd_flag_byte & 0x20:  # Symbol is an ETP.
        sd_flags.append('ETP')
    sd_flag_string = '|'.join(sd_flags)

    # Determine LULD tier.
    match luld_tier_int:
        case 0:  # Not applicable
            luld_tier = 'NOT_APPLICABLE'
        case 1:  # Tier 1 NMS Stock
            luld_tier = 'TIER1_NMS_STOCK'
        case 2:  # Tier 2 NMS Stock
            luld_tier = 'TIER2_NMS_STOCK'
        case _:
            raise Exception('Invalid Security Directory Message LULD Tier flag')

    # Create message string.
    message_string = f'D,{symbol},{round_lot_size},{adjusted_poc_price},{luld_tier},{sd_flag_string}'
    return timestamp_raw, message_string


def decode_trading_status_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Trading Status Message (message type 'H').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 22, "Trading Status Message payload size should be 22 bytes."

    # Extract data from the payload.
    trading_status_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    reason_raw = struct.unpack('<4s', message_payload[18:22])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    reason = reason_raw.decode().strip()

    # Determine trading status.
    match chr(trading_status_int):
        case 'H':  # Trading halted across all US equity markets.
            trading_status_string = 'HALTED'
        case 'O':  # Trading halt released into an Order Acceptance Period in IEX.
            trading_status_string = 'HALT_RELEASED_INTO_OAP'
        case 'P':  # Trading paused and Order Acceptance Period on IEX.
            trading_status_string = 'PAUSED'
        case 'T':  # Trading on IEX.
            trading_status_string = 'TRADING'
        case _:
            trading_status_string = ''

    # Create message string.
    message_string = f'H,{symbol},{trading_status_string},{reason}'
    return timestamp_raw, message_string


def decode_retail_liquidity_indicator_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Retail Liquidity Indicator Message (message type 'I').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 18, "Retail Liquidity Indicator Message payload size should be 18 bytes."

    # Extract data from the payload.
    retail_liquidity_indicator_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()

    # Determine retail liquidity indicator.
    match chr(retail_liquidity_indicator_int):
        case ' ':  # Retail indicator not applicable
            retail_liquidity_indicator_string = 'NOT_APPLICABLE'
        case 'A':  # Buy interest for Retail
            retail_liquidity_indicator_string = 'BUY_INTEREST'
        case 'B':  # Sell interest for Retail
            retail_liquidity_indicator_string = 'SELL_INTEREST'
        case 'C':  # Buy and sell interest for Retail
            retail_liquidity_indicator_string = 'BUY_INTEREST|SELL_INTEREST'
        case _:
            raise Exception('Invalid Retail Liquidity Indicator flag')

    # Create message string.
    message_string = f'I,{symbol},{retail_liquidity_indicator_string}'
    return timestamp_raw, message_string


def decode_operational_halt_status_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from an Operational Halt Status Message (message type 'O').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 18, "Operational Halt Status Message payload size should be 18 bytes."

    # Extract data from the payload.
    operational_halt_status_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()

    # Determine operational halt status.
    match chr(operational_halt_status_int):
        case 'O':  # IEX specific operational trading halt
            operational_halt_status_string = 'HALTED'
        case 'N':  # Not operationally halted on IEX
            operational_halt_status_string = 'NOT_HALTED'
        case _:
            raise Exception('Invalid Operational Halt Status Message flag')

    # Create message string.
    message_string = f'O,{symbol},{operational_halt_status_string}'
    return timestamp_raw, message_string


def decode_short_sale_price_test_status_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Short Sale Price Test Status Message (message type 'P').
    Return the raw_timestamp and the message string.
    """
    assert len(message_payload) == 19, "Short Sale Price Test Status Message payload size should be 19 bytes."

    # Extract data from the payload.
    short_sale_price_test_status = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    detail_int = message_payload[18]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()

    # Determine short sale price test status.
    match short_sale_price_test_status:
        case 0:  # Short Sale Price Test Not in Effect
            status_string = 'NOT_IN_EFFECT'
        case 1:  # Short Sale Price Test in Effect
            status_string = 'IN_EFFECT'
        case _:
            raise Exception('Invalid Short Sale Price Test Status flag')

    # Determine short sale price test detail.
    match chr(detail_int):
        case ' ':  # No price test in place
            detail_string = 'NO_PRICE_TEST'
        case 'A':  # Restriction in effect due to an intraday price drop in the security.
            detail_string = 'RES_ACTIVATED'
        case 'C':  # Restriction remains in effect from prior day.
            detail_string = 'RES_CONTINUED'
        case 'D':  # Restriction deactivated.
            detail_string = 'RES_DEACTIVATED'
        case 'N':  # Detail not available.
            detail_string = 'NOT_AVAILABLE'
        case _:
            raise Exception('Invalid Short Sale Price Test Detail flag')

    # Create message string.
    message_string = f'P,{symbol},{status_string},{detail_string}'
    return timestamp_raw, message_string


def decode_security_event_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Security Event Message (message type 'E').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 18, "Security Event Message payload size should be 18 bytes."

    # Extract data from the payload.
    security_event_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()

    # Determine security event.
    match chr(security_event_int):
        case 'O':  # Opening Process Complete
            security_event_string = 'OPENING'
        case 'C':  # Closing Process Complete
            security_event_string = 'CLOSING'
        case _:
            security_event_string = ''

    # Create message string.
    message_string = f'E,{symbol},{security_event_string}'
    return timestamp_raw, message_string


def decode_price_level_update(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Price Level Update Message (message type '8' or '5').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 30, "Price Level Update payload size should be 30 bytes."

    # Extract data from the payload.
    price_level_update_type = message_payload[0]
    event_flags = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    size = struct.unpack('<I', message_payload[18:22])[0]
    price_raw = struct.unpack('<Q', message_payload[22:30])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    price = round(price_raw * 1e-4, 2)

    # Determine record type based on size.
    if size == 0:
        record_type = 'Z'
    else:
        record_type = 'R'

    # Check event flags and construct event output string.
    match event_flags:
        case 1:  # Order Book is processing an event
            flag = 'IN_TRANSITION'
        case 0:  # Event processing complete
            flag = 'TRANS_COMPLETE'
        case _:
            raise Exception('Invalid event flag encountered in price level update message')

    # Create the message string.
    message_string = f'{price_level_update_type},{symbol},{price},{size},{record_type},{flag}'
    return timestamp_raw, message_string


def decode_trade_report_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Trade Report Message (message type 'T').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 38, "Trade Report Message payload size should be 38 bytes."

    # Extract data from the payload.
    sale_condition_flags = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    size = struct.unpack('<I', message_payload[18:22])[0]
    price_raw = struct.unpack('<Q', message_payload[22:30])[0]
    trade_id = struct.unpack('<q', message_payload[30:38])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    price = round(price_raw * 1e-4, 2)

    # Parse sale condition flags.
    sale_condition_string = _convert_sale_condition_flags(sale_condition_flags)

    # Create the message string.
    message_string = f'T,{symbol},{size},{price},{trade_id},{sale_condition_string}'
    return timestamp_raw, message_string


def decode_official_price_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from an Official Price Message (message type 'X').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 26, "Official Price Message payload size should be 26 bytes."

    # Extract data from the payload.
    price_type_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    official_price_raw = struct.unpack('<Q', message_payload[18:26])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    official_price = round(official_price_raw * 1e-4, 2)

    # Determine Price Type.
    match chr(price_type_int):
        case 'Q':  # Official opening price
            price_type_string = 'OPENING'
        case 'M':  # Official closing price
            price_type_string = 'CLOSING'
        case _:
            raise Exception('Invalid price type flag encountered in official price message')

    # Create the message string.
    message_string = f'X,{symbol},{official_price},{price_type_string}'
    return timestamp_raw, message_string


def decode_trade_break_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from a Trade Break Message (message type 'B').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 38, "Trade Break Message payload size should be 38 bytes."

    # Extract data from the payload.
    sale_condition_flags = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    size = struct.unpack('<I', message_payload[18:22])[0]
    price_raw = struct.unpack('<Q', message_payload[22:30])[0]
    trade_id = struct.unpack('<q', message_payload[30:38])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    price = round(price_raw * 1e-4, 2)

    # Parse sale condition flags.
    sale_condition_string = _convert_sale_condition_flags(sale_condition_flags)

    # Create the message string.
    message_string = f'B,{symbol},{size},{price},{trade_id},{sale_condition_string}'
    return timestamp_raw, message_string


def decode_auction_information_message(message_payload: bytes) -> (int, str):
    """Parses the message payload from an Auction Information Message (message type 'A').
    Returns the raw_timestamp and the message string.
    """
    assert len(message_payload) == 80, "Auction Information Message payload size should be 80 bytes."

    # Extract data from the payload.
    auction_type_int = message_payload[1]
    timestamp_raw = struct.unpack('<q', message_payload[2:10])[0]
    symbol_raw = struct.unpack('<8s', message_payload[10:18])[0]
    paired_shares = struct.unpack('<I', message_payload[18:22])[0]
    reference_price_raw = struct.unpack('<Q', message_payload[22:30])[0]
    ind_cl_price_raw = struct.unpack('<Q', message_payload[30:38])[0]
    imbalance_shares = struct.unpack('<I', message_payload[38:42])[0]
    imbalance_side_int = message_payload[42]
    extension_number = message_payload[43]
    scheduled_auction_time = struct.unpack('<I', message_payload[44:48])[0]
    auction_book_clearing_price_raw = struct.unpack('<Q', message_payload[48:56])[0]
    collar_reference_price_raw = struct.unpack('<Q', message_payload[56:64])[0]
    lower_auction_collar_raw = struct.unpack('<Q', message_payload[64:72])[0]
    upper_auction_collar_raw = struct.unpack('<Q', message_payload[72:80])[0]

    # Remove trailing null characters.
    symbol = symbol_raw.decode().strip()
    # Decimal point implied by always having 4 decimal places.
    reference_price = round(reference_price_raw * 1e-4, 2)
    ind_cl_price = round(ind_cl_price_raw * 1e-4, 2)
    auction_book_clearing_price = round(auction_book_clearing_price_raw * 1e-4, 2)
    collar_reference_price = round(collar_reference_price_raw * 1e-4, 2)
    lower_auction_collar = round(lower_auction_collar_raw * 1e-4, 2)
    upper_auction_collar = round(upper_auction_collar_raw * 1e-4, 2)

    # Determine auction type.
    match chr(auction_type_int):
        case 'O':  # Opening Auction
            auction_type_string = 'OPENING'
        case 'C':  # Closing Auction
            auction_type_string = 'CLOSING'
        case 'I':  # IPO Auction
            auction_type_string = 'IPO'
        case 'H':  # Halt Auction
            auction_type_string = 'HALT'
        case 'V':  # Volatility Auction
            auction_type_string = 'VOLATILITY'
        case _:
            raise Exception('Invalid auction type flag encountered in auction information message')

    # Determine imbalance side.
    match chr(imbalance_side_int):
        case 'B':  # buy-side imbalance
            imbalance_side_string = 'BUY'
        case 'S':  # sell-side imbalance
            imbalance_side_string = 'SELL'
        case 'N':  # no imbalance
            imbalance_side_string = 'NONE'
        case _:
            raise Exception('Invalid imbalance side flag encountered in official price message')

    # Create the message string.
    message_string = (f'A,{auction_type_string},{symbol},{paired_shares},{reference_price},{ind_cl_price},'
                      f'{imbalance_shares},{imbalance_side_string},{extension_number},'
                      f'{scheduled_auction_time},{auction_book_clearing_price},{collar_reference_price},'
                      f'{lower_auction_collar},{upper_auction_collar}')
    return timestamp_raw, message_string


#############################
### Functions for DEEP
#############################
def get_decoder(message_type: str):
    """Returns the decoder function for the given message_type.
    """
    match message_type:
        # Administrative Message Formats
        case 'S':
            return decode_system_event_message
        case 'D':
            return decode_security_directory_message
        case 'H':
            return decode_trading_status_message
        case 'I':
            return decode_retail_liquidity_indicator_message
        case 'O':
            return decode_operational_halt_status_message
        case 'P':
            return decode_short_sale_price_test_status_message
        case 'E':
            return decode_security_event_message
        # Trading Message Formats
        case '8':
            return decode_price_level_update
        case '5':
            return decode_price_level_update
        case 'T':
            return decode_trade_report_message
        case 'X':
            return decode_official_price_message
        case 'B':
            return decode_trade_break_message
        # Auction Message Formats
        case 'A':
            return decode_auction_information_message

        case _:
            raise Exception('Unknown DEEP message type')


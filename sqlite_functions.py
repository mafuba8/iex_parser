# Helper functions for storing IEX data messages into a SQLite database.
#
# Benedikt Otto - b.otto.code@protonmail.com - https://github.com/mafuba8
#
import sqlite3


def create_table(db_connection: sqlite3.Connection, table_name: str):
    """Creates a table within the database given by the given connection object.
    We can also give the message type character instead of the table name.
    """
    db_cursor = db_connection.cursor()
    match table_name:
        # System Event Messages (S)
        case 'system_event' | 'S':
            db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_event(
              date TEXT, time TEXT,
              system_event_type TEXT
            );''')

        # Security Directory Messages (D)
        case 'security_directory' | 'D':
            db_cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_directory(
              date TEXT, time TEXT,
              test_security INT, issued_security INT, etp INT,
              symbol TEXT, round_lot_size INT, adjusted_poc_price REAL, luld_tier INT
            );''')

        # Trading Status Messages (H)
        case 'trading_status' | 'H':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS trading_status(
                  date TEXT, time TEXT,
                  trading_status TEXT, symbol TEXT, reason TEXT
                );''')

        # Retail Liquidity Indicator Messages (I)
        case 'retail_liquidity_indicator' | 'I':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS retail_liquidity_indicator(
                  date TEXT, time TEXT,
                  retail_liquidity_indicator TEXT, symbol TEXT
                );''')

        # Operational Halt Status Messages (O)
        case 'operational_halt_status' | 'O':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS operational_halt_status(
                  date TEXT, time TEXT,
                  operational_halt_status TEXT, symbol TEXT
                );''')

        # Short Sale Price Test Status Messages (P)
        case 'short_sale_price_test_status' | 'P':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS short_sale_price_test_status(
                  date TEXT, time TEXT,
                  in_effect INT, symbol TEXT, price_test_detail TEXT
                );''')

        # Security Event Messages (E)
        case 'security_event' | 'E':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_event(
                  date TEXT, time TEXT,
                  security_event TEXT, symbol TEXT
                );''')

        # Quote Update Messages (Q)
        case 'quote_update' | 'Q':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS quote_update(
                  date TEXT, time TEXT,
                  halted INT, active INT, pre_post_market INT, regular_market INT,
                  symbol TEXT, bid_size INT, bid_price REAL, ask_size INT, ask_price REAL
                );''')

        # Price Level Update Messages (Buy: 8, Sell: 5)
        case 'price_level_update' | '8' | '5':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS price_level_update(
                  date TEXT, time TEXT,
                  in_transition INT, type TEXT, symbol TEXT, size INT, price REAL
                );''')

        # Trade Report Messages (T)
        case 'trade_report' | 'T':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS trade_report(
                  date TEXT, time TEXT,
                  intermarket_sweep INT, extended_hours INT, odd_lot INT, trade_through_exempt INT,
                  single_price_cross INT, symbol TEXT, size INT, price REAL, trade_id INT
                );''')

        # Official Price Messages (X)
        case 'official_price' | 'X':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS official_price(
                  date TEXT, time TEXT,
                  price_type TEXT, symbol TEXT, official_price REAL
                );''')

        # Trade Break Messages (B)
        case 'trade_break' | 'B':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS trade_break(
                  date TEXT, time TEXT,
                  intermarket_sweep INT, extended_hours INT, odd_lot INT, trade_through_exempt INT,
                  single_price_cross INT, symbol TEXT, size INT, price REAL, trade_id INT
                );''')

        # Auction Information Messages (A)
        case 'auction_information' | 'A':
            db_cursor.execute('''
                CREATE TABLE IF NOT EXISTS auction_information(
                  date TEXT, time TEXT,
                  auction_type TEXT, symbol TEXT, paired_shares INT, reference_price REAL, indicative_clearing_price REAL,
                  imbalance_shares INT, imbalance_side TEXT, extension_number INT, scheduled_auction_time TEXT,
                  auction_book_clearing_price REAL, collar_reference_price REAL, lower_auction_collar REAL,
                  upper_auction_collar REAL
                );''')


def insert_row(db_connection: sqlite3.Connection, table_name: str, data_dict: dict):
    """Inserts the data from the dictionary into the table.
    We can also give the message type character instead of the table name.
    """
    db_cursor = db_connection.cursor()
    match table_name:
        # System Event Messages (S)
        case 'system_event' | 'S':
            db_cursor.execute('''
                INSERT INTO system_event (
                  date, time,
                  system_event_type
                ) VALUES (
                  :date, :time,
                  :system_event_type
                );''', data_dict)

        # Security Directory Messages (D)
        case 'security_directory' | 'D':
            db_cursor.execute('''
                INSERT INTO security_directory (
                  date, time,
                  test_security, issued_security, etp, symbol, round_lot_size,
                  adjusted_poc_price, luld_tier
                ) VALUES (
                  :date, :time,
                  :test_security, :issued_security, :etp, :symbol, :round_lot_size,
                  :adjusted_poc_price, :luld_tier
                );''', data_dict)

        # Trading Status Messages (H)
        case 'trading_status' | 'H':
            db_cursor.execute('''
                INSERT INTO trading_status (
                  date, time,
                  trading_status, symbol, reason
                ) VALUES (
                  :date, :time,
                  :trading_status, :symbol, :reason
                );''', data_dict)

        # Retail Liquidity Indicator Messages (I)
        case 'retail_liquidity_indicator' | 'I':
            db_cursor.execute('''
                INSERT INTO retail_liquidity_indicator (
                  date, time,
                  retail_liquidity_indicator, symbol
                ) VALUES (
                  :date, :time,
                  :retail_liquidity_indicator, :symbol
                );''', data_dict)

        # Operational Halt Status Messages (O)
        case 'operational_halt_status' | 'O':
            db_cursor.execute('''
                INSERT INTO operational_halt_status (
                  date, time,
                  operational_halt_status, symbol
                ) VALUES (
                  :date, :time,
                  :operational_halt_status, :symbol
                );''', data_dict)

        # Short Sale Price Test Status Messages (P)
        case 'short_sale_price_test_status' | 'P':
            db_cursor.execute('''
                INSERT INTO short_sale_price_test_status (
                  date, time,
                  in_effect, symbol, price_test_detail
                ) VALUES (
                  :date, :time,
                  :in_effect, :symbol, :price_test_detail
                );''', data_dict)

        # Security Event Messages (E)
        case 'security_event' | 'E':
            db_cursor.execute('''
                INSERT INTO security_event (
                  date, time,
                  security_event, symbol
                ) VALUES (
                  :date, :time,
                  :security_event, :symbol
                );''', data_dict)

        # Quote Update Messages (Q)
        case 'quote_update' | 'Q':
            db_cursor.execute('''
                INSERT INTO quote_update (
                  date, time,
                  halted, active, pre_post_market, regular_market,
                  symbol, bid_size, bid_price, ask_size, ask_price
                ) VALUES (
                  :date, :time,
                  :halted, :active, :pre_post_market, :regular_market,
                  :symbol, :bid_size, :bid_price, :ask_size, :ask_price
                );''', data_dict)

        # Price Level Update Messages (Buy: 8, Sell: 5)
        case 'price_level_update' | '8' | '5':
            db_cursor.execute('''
                INSERT INTO price_level_update (
                  date, time,
                  in_transition, type, symbol, size, price
                ) VALUES (
                  :date, :time,
                  :in_transition, :type, :symbol, :size, :price
                );''', data_dict)

        # Trade Report Messages (T)
        case 'trade_report' | 'T':
            db_cursor.execute('''
                INSERT INTO trade_report (
                  date, time,
                  intermarket_sweep, extended_hours, odd_lot, trade_through_exempt,
                  single_price_cross, symbol, size, price, trade_id
                ) VALUES (
                  :date, :time,
                  :intermarket_sweep, :extended_hours, :odd_lot, :trade_through_exempt,
                  :single_price_cross, :symbol, :size, :price, :trade_id
                );''', data_dict)

        # Official Price Messages (X)
        case 'official_price' | 'X':
            db_cursor.execute('''
                INSERT INTO official_price (
                  date, time,
                  price_type, symbol, official_price
                ) VALUES (
                  :date, :time,
                  :price_type, :symbol, :official_price
                );''', data_dict)

        # Trade Break Messages (B)
        case 'trade_break' | 'B':
            db_cursor.execute('''
                INSERT INTO trade_break (
                  date, time,
                  intermarket_sweep, extended_hours, odd_lot, trade_through_exempt,
                  single_price_cross, symbol, size, price, trade_id
                ) VALUES (
                  :date, :time,
                  :intermarket_sweep, :extended_hours, :odd_lot, :trade_through_exempt,
                  :single_price_cross, :symbol, :size, :price, :trade_id
                );''', data_dict)

        # Auction Information Messages (A)
        case 'auction_information' | 'A':
            db_cursor.execute('''
                INSERT INTO auction_information (
                  date, time,
                  auction_type, symbol, paired_shares, reference_price, indicative_clearing_price,
                  imbalance_shares, imbalance_side, extension_number, scheduled_auction_time,
                  auction_book_clearing_price, collar_reference_price, lower_auction_collar,
                  upper_auction_collar
                ) VALUES (
                  :date, :time,
                  :auction_type, :symbol, :paired_shares, :reference_price, :indicative_clearing_price,
                  :imbalance_shares, :imbalance_side, :extension_number, :scheduled_auction_time,
                  :auction_book_clearing_price, :collar_reference_price, :lower_auction_collar,
                  :upper_auction_collar
                );''', data_dict)

    # Commit the INSERT transactions.
    db_connection.commit()


def insert_rows(db_connection: sqlite3.Connection, table_name: str, list_of_dicts: list[dict]):
    """Inserts the data from the list of dictionaries into the table.
    We can also give the message type character instead of the table name.
    """
    db_cursor = db_connection.cursor()
    match table_name:
        # System Event Messages (S)
        case 'system_event' | 'S':
            db_cursor.executemany('''
                INSERT INTO system_event (
                  date, time,
                  system_event_type
                ) VALUES (
                  :date, :time,
                  :system_event_type
                );''', list_of_dicts)

        # Security Directory Messages (D)
        case 'security_directory' | 'D':
            db_cursor.executemany('''
                INSERT INTO security_directory (
                  date, time,
                  test_security, issued_security, etp, symbol, round_lot_size,
                  adjusted_poc_price, luld_tier
                ) VALUES (
                  :date, :time,
                  :test_security, :issued_security, :etp, :symbol, :round_lot_size,
                  :adjusted_poc_price, :luld_tier
                );''', list_of_dicts)

        # Trading Status Messages (H)
        case 'trading_status' | 'H':
            db_cursor.executemany('''
                INSERT INTO trading_status (
                  date, time,
                  trading_status, symbol, reason
                ) VALUES (
                  :date, :time,
                  :trading_status, :symbol, :reason
                );''', list_of_dicts)

        # Retail Liquidity Indicator Messages (I)
        case 'retail_liquidity_indicator' | 'I':
            db_cursor.executemany('''
                INSERT INTO retail_liquidity_indicator (
                  date, time,
                  retail_liquidity_indicator, symbol
                ) VALUES (
                  :date, :time,
                  :retail_liquidity_indicator, :symbol
                );''', list_of_dicts)

        # Operational Halt Status Messages (O)
        case 'operational_halt_status' | 'O':
            db_cursor.executemany('''
                INSERT INTO operational_halt_status (
                  date, time,
                  operational_halt_status, symbol
                ) VALUES (
                  :date, :time,
                  :operational_halt_status, :symbol
                );''', list_of_dicts)

        # Short Sale Price Test Status Messages (P)
        case 'short_sale_price_test_status' | 'P':
            db_cursor.executemany('''
                INSERT INTO short_sale_price_test_status (
                  date, time,
                  in_effect, symbol, price_test_detail
                ) VALUES (
                  :date, :time,
                  :in_effect, :symbol, :price_test_detail
                );''', list_of_dicts)

        # Security Event Messages (E)
        case 'security_event' | 'E':
            db_cursor.executemany('''
                INSERT INTO security_event (
                  date, time,
                  security_event, symbol
                ) VALUES (
                  :date, :time,
                  :security_event, :symbol
                );''', list_of_dicts)

        # Quote Update Messages (Q)
        case 'quote_update' | 'Q':
            db_cursor.executemany('''
                INSERT INTO quote_update (
                  date, time,
                  halted, active, pre_post_market, regular_market,
                  symbol, bid_size, bid_price, ask_size, ask_price
                ) VALUES (
                  :date, :time,
                  :halted, :active, :pre_post_market, :regular_market,
                  :symbol, :bid_size, :bid_price, :ask_size, :ask_price
                );''', list_of_dicts)

        # Price Level Update Messages (Buy: 8, Sell: 5)
        case 'price_level_update' | '8' | '5':
            db_cursor.executemany('''
                INSERT INTO price_level_update (
                  date, time,
                  in_transition, type, symbol, size, price
                ) VALUES (
                  :date, :time,
                  :in_transition, :type, :symbol, :size, :price
                );''', list_of_dicts)

        # Trade Report Messages (T)
        case 'trade_report' | 'T':
            db_cursor.executemany('''
                INSERT INTO trade_report (
                  date, time,
                  intermarket_sweep, extended_hours, odd_lot, trade_through_exempt,
                  single_price_cross, symbol, size, price, trade_id
                ) VALUES (
                  :date, :time,
                  :intermarket_sweep, :extended_hours, :odd_lot, :trade_through_exempt,
                  :single_price_cross, :symbol, :size, :price, :trade_id
                );''', list_of_dicts)

        # Official Price Messages (X)
        case 'official_price' | 'X':
            db_cursor.executemany('''
                INSERT INTO official_price (
                  date, time,
                  price_type, symbol, official_price
                ) VALUES (
                  :date, :time,
                  :price_type, :symbol, :official_price
                );''', list_of_dicts)

        # Trade Break Messages (B)
        case 'trade_break' | 'B':
            db_cursor.executemany('''
                INSERT INTO trade_break (
                  date, time,
                  intermarket_sweep, extended_hours, odd_lot, trade_through_exempt,
                  single_price_cross, symbol, size, price, trade_id
                ) VALUES (
                  :date, :time,
                  :intermarket_sweep, :extended_hours, :odd_lot, :trade_through_exempt,
                  :single_price_cross, :symbol, :size, :price, :trade_id
                );''', list_of_dicts)

        # Auction Information Messages (A)
        case 'auction_information' | 'A':
            db_cursor.executemany('''
                INSERT INTO auction_information (
                  date, time,
                  auction_type, symbol, paired_shares, reference_price, indicative_clearing_price,
                  imbalance_shares, imbalance_side, extension_number, scheduled_auction_time,
                  auction_book_clearing_price, collar_reference_price, lower_auction_collar,
                  upper_auction_collar
                ) VALUES (
                  :date, :time,
                  :auction_type, :symbol, :paired_shares, :reference_price, :indicative_clearing_price,
                  :imbalance_shares, :imbalance_side, :extension_number, :scheduled_auction_time,
                  :auction_book_clearing_price, :collar_reference_price, :lower_auction_collar,
                  :upper_auction_collar
                );''', list_of_dicts)

    # Commit the INSERT transactions.
    db_connection.commit()

import os

# Server Configuration
HOST = '127.0.0.1'
PORT = 65432
BUFFER_SIZE = 1024

# Tau Configuration
TAU_PROGRAM_FILE = 'tool_code.tau'  # Assumes it's in the same directory or adjust path
TAU_DOCKER_IMAGE = 'tau'
CONTAINER_WORKDIR = '/data'
TAU_READY_SIGNAL = "Execution step: 0"  # String Tau prints when ready for input

# Timeout Configuration
PROCESS_TIMEOUT = 120 # Timeout for Tau process startup
COMM_TIMEOUT = 99999    # Timeout in seconds for waiting for Tau response during communication
CLIENT_WAIT_TIMEOUT = 10 # Timeout for clients waiting for Tau to become ready
SHUTDOWN_TIMEOUT = 1  # Max seconds to wait for manager thread cleanup
 
# Data directory and SQLite database path for string mappings and future state (mempool, blocks, balances)
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

DEFAULT_PROD_DB_PATH = "strings.db"

STRING_DB_PATH = os.environ.get("TAU_DB_PATH", DEFAULT_PROD_DB_PATH)

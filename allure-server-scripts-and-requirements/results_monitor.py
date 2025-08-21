import json
import datetime
import subprocess
from pathlib import Path
from shared_logger import logger

def load_state(state_file):
    """
    Load previous results state from JSON file
    """
    if Path(state_file).exists():
        try:
            with open(state_file) as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error loading state file: {e}")
            return {}
    return {}

def save_state(state_file, current_state):
    """
    Save current results state to JSON file
    """
    with open(state_file, 'w') as f:
        json.dump(current_state, f, indent=2)

def get_latest_modification(directory, exclude_files="environment.properties"):
    """
    Get latest modification time
    """
    try:
        cmd = f"find {directory} -type f ! -name '{exclude_files}' -printf '%T@ %p\n' | sort -nr | head -n 1"
        result = subprocess.check_output(cmd, shell=True, text=True)
        if result.strip():
            unix_timestamp, filepath = result.strip().split(' ', 1)
            utc_time = datetime.datetime.fromtimestamp(
                float(unix_timestamp), 
                tz=datetime.timezone.utc
            )
            return utc_time.isoformat(), filepath
    except subprocess.CalledProcessError as e:
        logger.error(f"Error checking modifications: {e}")
    return "", ""

def check_directory_changes(directory, state_file="allure-results-state.json"):
    """
    Check if results have changed since last check

    Args:
        directory: Directory to check for changes
        state_file: Path to the state file
        
    Returns:
        Dictionary containing change status, timestamp and filepath
        None if directory doesn't exist or error occurs
    """
    if not Path(directory).exists():
        logger.error(f"Error: Directory {directory} does not exist")
        return None

    # Load previous state
    current_state = load_state(state_file)  # Load existing state

    # Get latest modification
    timestamp, filepath = get_latest_modification(directory)
    if not timestamp:
        return None

    # Update state only for this directory
    dir_key = str(directory)
    
    # Check if changed
    is_changed = (
        dir_key not in current_state or
        current_state[dir_key]["timestamp"] != timestamp
    )

    # Update only this directory's state while preserving others
    current_state[dir_key] = {
        "timestamp": timestamp,
        "last_modified_file": filepath
    }

    # Save updated state
    save_state(state_file, current_state)

    return {
        "changed": is_changed,
        "timestamp": timestamp,
        "filepath": filepath
    }

if __name__ == "__main__":
    main()

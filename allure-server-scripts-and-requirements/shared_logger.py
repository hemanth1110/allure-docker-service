import sys
import os
from datetime import datetime
from loguru import logger

def setup_shared_logger():
    # Get timestamp from environment variable or create new one
    run_timestamp = os.environ.get('RUN_TIMESTAMP')
    if not run_timestamp:
        run_timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        os.environ['RUN_TIMESTAMP'] = run_timestamp
    
    log_file = f"logs/allure-{run_timestamp}.log"
    
    # Configure logger only once
    if not hasattr(logger, '_configured'):
        os.makedirs("logs", exist_ok=True)
        logger.remove(0)
        
        # Add file handler
        logger.add(log_file, retention = "14 days",
                format="<green>{time:YYYY-MM-DDTHH:mm:ssZ!UTC}</green> | <level>{level}</level> | <level>{message}</level>",
                level='DEBUG')
        
        # Add console handler
        logger.add(sys.stdout,
                format="<green>{time:YYYY-MM-DDTHH:mm:ssZ!UTC}</green> | <level>{level}</level> | <level>{message}</level>",
                level='DEBUG')
        
        logger._configured = True
    
    return logger

# Set up logger when module is imported
logger = setup_shared_logger()
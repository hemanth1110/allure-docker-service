"""
Allure Results Processor

This script processes Allure test results by scanning the allure-results directory,
identifying platform-specific test result folders, and generating appropriate Allure reports.
It looks for results organized by platform (macos, windows) and version (e.g., lens-2.1.x-results).

Usage:
    python process_allure_results.py
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from results_monitor import check_directory_changes
from lock_processor import acquire_lock, release_lock
from shared_logger import logger

def main():
    """
    Main function that orchestrates the Allure report generation process.
    
    This function:
    1. Validates the existence of the allure-results directory
    2. Searches for platform-specific directories (macos, windows)
    3. Identifies version-specific test result folders using regex pattern matching
    4. Generates appropriate Allure reports by calling the generateReport.py script
       with the correct parameters for each platform and version combination
    
    Returns:
        None
    """

    lock_file = '/tmp/process_allure_results.lock'
    
    logger.info("Attempting to acquire lock...")

    lock_fd = acquire_lock(lock_file)

    if not lock_fd:
        logger.warning("Could not acquire lock. Another instance is running.")
        return

    try:
        logger.info("Lock acquired successfully")

        logger.info("Processing Allure results...")
        
        allure_results_path = Path("allure-results")
        
        # Check if allure-results directory exists and is valid
        if not allure_results_path.exists() or not allure_results_path.is_dir():
            logger.error(f"Error: {allure_results_path} does not exist or is not a directory")
            return

        # Regular expression to extract testType and version from folder names like 'lens-2.1.x-results' or 'dfu-lens-2.1.x-results'
        pattern = re.compile(r'(?:(\w+)-)?lensr?-(\d+\.\d+)\.x-results')
        
        for platform_dir in allure_results_path.iterdir():
            # Process only platform-specific directories (macos, windows)
            if platform_dir.is_dir() and platform_dir.name in ["macos", "windows"]:
                logger.info(f"Processing platform: {platform_dir.name}")

                logger.debug(f"Platform directory: {platform_dir}")

                for folder in platform_dir.iterdir():
                    # Check each folder within the platform directory
                    if folder.is_dir():
                        match = pattern.match(folder.name)
                        
                        # Process only folders matching the version pattern
                        if match:
                            change_result = check_directory_changes(folder)
                            
                            logger.debug(f"Change result for {folder.name}: {change_result}")

                            if not change_result["changed"]:
                                logger.info(f"No changes detected in {folder.name}, skipping...")
                                continue

                            # Extract testType (if exists) and version from the regex groups
                            test_type = match.group(1)  # Optional testType prefix
                            version = match.group(2)    # Version number (e.g., 2.1)
                            
                            # Convert dots to dashes for project ID naming convention followed by allure docker service
                            dashed_version = version.replace('.', '-')

                            # Determine project prefix based on folder name
                            if 'lensr-' in folder.name:
                                project_prefix = "lr"
                            else:
                                project_prefix = "ld"

                            # Construct project ID with testType prefix if it exists
                            if test_type:
                                project_id = f"{test_type}-{platform_dir.name}-{project_prefix}-v-{dashed_version}-x"
                            else:
                                project_id = f"{platform_dir.name}-{project_prefix}-v-{dashed_version}-x"

                            # Construct command to generate Allure report with proper versioning
                            command = f"/home/alfonso/DMaas/.venv/bin/python3 generateReport.py --lens-version {version} --project-id {project_id} --platform {platform_dir.name} --folder-name {folder.name}"

                            logger.info(f"Processing folder: {folder.name}")
                            logger.info(f"Running command: {command}")
                            
                            try:
                                # Execute the report generation command
                                subprocess.run(command, shell=True, check=True, env=os.environ.copy())
                                logger.info("Command executed successfully")

                            except subprocess.CalledProcessError as e:
                                logger.error(f"Error executing command: {e}")

    finally:
        logger.info("Releasing lock...")
        release_lock(lock_fd, lock_file)
        logger.info("Lock released")

        logger.info(f"Process completed at: {subprocess.check_output('date', shell=True).decode().strip()}")

if __name__ == "__main__":
    main()

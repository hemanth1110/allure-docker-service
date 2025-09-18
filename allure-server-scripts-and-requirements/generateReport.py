import os
import subprocess
import requests
import sys
import argparse
import time
import shutil
from shared_logger import logger

# Define the directory where remote test results are stored
remote_test_results_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'allure-results')

# Define constants for execution name and source
execution_name = 'TCS'
execution_from = 'https://tcs.polycom.com'

# Define API endpoints for generating reports and cleaning results
api_endpoint_gr = 'http://localhost:5050/generate-report'
api_endpoint_clean = 'http://localhost:5050/clean-results'

def process_folder(folder_name, project_id, platform):
    """
    Process a specific folder by sending results, generating a report, and cleaning results.
    """
    folder_path = os.path.join(remote_test_results_dir, platform, folder_name)
    logger.info(f"Folder path: {folder_path}")
    logger.info(f"Is folder: {os.path.isdir(folder_path)}")

    if os.path.isdir(folder_path):
        logger.info(f"Processing folder: {folder_name}")
        subprocess.run(['project_venv_path', 'send_results.py', '--results-path', folder_path, '--project-id', project_id], env=os.environ.copy()) # replace with venv python path
        generate_report(folder_name, project_id)
        clean_results(project_id)

def generate_report(folder_name, project_id):
    """
    Generate an Allure report for the specified folder and project ID.
    """
    custom_build_order = folder_name.split('.')[-1]
    params = {
        'project_id': project_id,
        'execution_name': execution_name,
        'execution_from': execution_from,
        'custom_build_order': custom_build_order
    }

    response = requests.get(api_endpoint_gr, params=params)

    if response.status_code == 200:
        logger.success("Report generated successfully.")
    else:
        logger.error(f"Failed to generate report. Status code: {response.status_code}, Response: {response.text}")

def clean_results(project_id):
    """
    Clean test results for the specified project ID from the Allure server.
    """
    params = {
        'project_id': project_id
    }
    response = requests.get(api_endpoint_clean, params=params)

    if response.status_code == 200:
        logger.success("Results cleaned successfully.")
    else:
        logger.error(f"Failed to clean results. Status code: {response.status_code}, Response: {response.text}")

def clean_history(project_id):
    """
    Clean the history for the specified project ID from the Allure server.
    """
    api_endpoint_delete_history = f'http://localhost:5050/projects/{project_id}'
    response = requests.delete(api_endpoint_delete_history)

    if response.status_code == 200:
        logger.success("History cleaned successfully.")
    else:
        logger.error(f"Failed to clean history. Status code: {response.status_code}, Response: {response.text}")

def main():
    """
    Main function to parse command line arguments and execute the appropriate logic.
    """
    parser = argparse.ArgumentParser(description='Generate and clean test reports.')
    
    # Define command line arguments
    parser.add_argument('--clean-history', type=str, choices=['true', 'false'], help='Clean history if true')
    parser.add_argument('--lens-version', type=str, help='Specify the lens version')
    parser.add_argument('--project-id', type=str, required=True, help='Specify the project ID')
    parser.add_argument('--platform', type=str, help='Specify the platform (e.g., windows, macos)')
    parser.add_argument('--folder-name', type=str, help='Specify the exact folder name to process (e.g., DFU-lens-2.3.x-results)')

    args = parser.parse_args()

    # If clean-history flag is set to true, clear the history for the specified project
    if args.clean_history and args.clean_history.lower() == 'true':
        clean_history(args.project_id)

    elif args.lens_version:
        lens_version = args.lens_version
        
        # Determine target folder and prefix
        if args.folder_name:
            target_folder = args.folder_name
            folder_prefix = 'lensr' if 'lensr-' in target_folder else 'lens'
        else:
            # Check for both lens- and lensr- folder patterns
            lens_folder = f'lens-{lens_version}.x-results'
            lensr_folder = f'lensr-{lens_version}.x-results'
            
            lens_path = os.path.join(remote_test_results_dir, args.platform, lens_folder)
            lensr_path = os.path.join(remote_test_results_dir, args.platform, lensr_folder)
            
            if os.path.exists(lensr_path):
                target_folder = lensr_folder
                folder_prefix = 'lensr'
            elif os.path.exists(lens_path):
                target_folder = lens_folder
                folder_prefix = 'lens'
            else:
                logger.error(f"Error: Neither {lens_path} nor {lensr_path} exists")
                return
        
        # Set the versioned directory path and validate
        remote_test_results_dir_versioned = os.path.join(remote_test_results_dir, args.platform, target_folder)
        
        if not os.path.exists(remote_test_results_dir_versioned):
            logger.error(f"Error: Specified folder {remote_test_results_dir_versioned} does not exist")
            return
            
        logger.info(f"Looking for test results in: {remote_test_results_dir_versioned} ({folder_prefix} variant)")
        
        # Get all result folders and sort them by build number (last 4 characters)
        folders = sorted(os.listdir(remote_test_results_dir_versioned), key=lambda x: x[-4:])
        
        # Create a timestamped project ID to avoid conflicts
        timestamp = time.strftime("%H%M%S")
        new_project_id = f"{args.project_id}-{timestamp}"

        # Process each result folder for the specified lens version
        for folder_name in folders:
            folder_path = os.path.join(remote_test_results_dir_versioned, folder_name)
            logger.info(f"Processing test results from: {folder_path}")
            
            # Create/update environment properties file with version and platform info
            env_file_path = os.path.join(folder_path, 'environment.properties')

            if os.path.exists(env_file_path):
                logger.info(f"{env_file_path} already exists.")
            
            else:
                # Create new file
                with open(env_file_path, 'w') as env_file:
                    if folder_prefix == 'lens':
                        env_file.write(f'lens-desktop-version={folder_name}\n')
                    elif folder_prefix == 'lensr':
                        env_file.write(f'lens-room-version={folder_name}\n')
                    env_file.write(f'operating-system={args.platform}')
                
            # Send test results to Allure server and generate report using the correct folder prefix
            if args.folder_name:
                # Use the provided folder name directly
                process_folder(f'{args.folder_name}/{folder_name}', new_project_id, args.platform)
            else:
                # Use the detected folder prefix for backwards compatibility
                process_folder(f'{folder_prefix}-{lens_version}.x-results/{folder_name}', new_project_id, args.platform)

        # Check if the target project already exists in Allure server
        search_endpoint = 'http://localhost:5050/allure-docker-service/projects'
        response = requests.get(search_endpoint)

        isProjectAvailable = True
       
        if response.status_code == 200:
            projects = response.json().get('data', {}).get('projects', {})

            if args.project_id in projects:
                logger.info(f"Project {args.project_id} already exists.")
            else:
                isProjectAvailable = False
                logger.info(f"Project {args.project_id} does not exist.")

        if not isProjectAvailable:
            create_endpoint = 'http://localhost:5050/allure-docker-service/projects'
            response = requests.post(create_endpoint, json={'id': args.project_id})

            if response.status_code == 201:
                logger.success(f"Project {args.project_id} created successfully.")
            else:
                logger.error(f"Failed to create project. Status code: {response.status_code}, Response: {response.text}")

        # Synchronize the new project directory with the existing project directory
        project_dir = os.path.join('projects_path', args.project_id) # replace with DMaas projects path
        new_project_dir = os.path.join('projects_path', new_project_id) # replace with DMaas projects path

        for filename in os.listdir(project_dir):
            file_path = os.path.join(project_dir, filename)

            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)

        for filename in os.listdir(new_project_dir):
            src_file = os.path.join(new_project_dir, filename)
            dest_file = os.path.join(project_dir, filename)

            if os.path.isfile(src_file):
                shutil.copy2(src_file, dest_file)
            elif os.path.isdir(src_file):
                shutil.copytree(src_file, dest_file)

        # Remove the temporary new project directory
        shutil.rmtree(new_project_dir)
            
    else:
        logger.error("Error: --lens-version argument is required if --clean-history is not true.")

if __name__ == "__main__":
    main()

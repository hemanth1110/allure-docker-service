import os
import requests
import json
import base64
import argparse
from shared_logger import logger

def get_results_directory_path(allure_results_directory):
    """
    Constructs the absolute path to the Allure results directory.
    
    Args:
        allure_results_directory (str): Relative path to the Allure results directory
        
    Returns:
        str: The absolute path to the Allure results directory
    """
    current_directory = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(current_directory, allure_results_directory)

def read_files_from_directory(results_directory):
    """
    Reads all files from the specified directory and encodes them in base64.
    
    Args:
        results_directory (str): Path to the directory containing Allure result files
        
    Returns:
        list: A list of dictionaries, where each dictionary contains the file name
              and the base64-encoded content of a result file
    """
    files = os.listdir(results_directory)
    results = []

    for file in files:
        file_path = os.path.join(results_directory, file)

        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                    
                    if content.strip():
                        b64_content = base64.b64encode(content)
                        result = {
                            'file_name': file,
                            'content_base64': b64_content.decode('UTF-8')
                        }
                        results.append(result)
            finally:
                f.close()
    
    return results

def send_results_to_allure_server(allure_server, project_id, results):
    """
    Sends the encoded test results to the Allure server.
    
    Args:
        allure_server (str): URL of the Allure server
        project_id (str): ID of the project to send the results to
        results (list): List of dictionaries containing the file names and encoded contents
        
    Returns:
        Response: HTTP response from the Allure server
    """
    headers = {'Content-type': 'application/json'}
    request_body = {
        "results": results
    }

    json_request_body = json.dumps(request_body)
    ssl_verification = True

    response = requests.post(
        f'{allure_server}/allure-docker-service/send-results?project_id={project_id}&force_project_creation=true',
        headers=headers,
        data=json_request_body,
        verify=ssl_verification
    )

    return response

def print_response(response):
    """
    Process and print the HTTP response from the Allure server in a formatted JSON.
    
    Args:
        response: HTTP response object from the Allure server
    """
    json_response_body = json.loads(response.content)
    json_prettier_response_body = json.dumps(json_response_body, indent=4, sort_keys=True)
    # Log the formatted JSON response
    logger.info(json_prettier_response_body)

def main():
    """
    Main function to handle command-line arguments and orchestrate the process
    of sending Allure test results to the Allure server.
    """
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send Allure results to Allure server.')
    parser.add_argument('--results-path', type=str, help='The path of the test results to send.')
    parser.add_argument('--project-id', type=str, help='The project ID to send the results to.')

    # Parse the provided arguments
    args = parser.parse_args()

    # Get the absolute path to the results directory
    results_directory = get_results_directory_path(args.results_path)

    # Read and encode all result files from the directory
    results = read_files_from_directory(results_directory)

    # Define the Allure server URL
    allure_server = 'http://localhost:5050'
    
    # Send the results to the Allure server
    response = send_results_to_allure_server(allure_server, args.project_id, results)
    
    # Display the server response
    # print_response(response)

if __name__ == "__main__":
    main()

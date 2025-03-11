import http.client  # Importing the HTTP client library
import datetime  # Importing datetime for timestamp logging

# Define the target host and port
host = "localhost"
port = 8000

# List of blocked keywords and their associated attack types
blocked_malware = {
    "class.module.classLoader": "Remote Code Execution Attack",
    "getRuntime().exec": "Command Injection Attack",
    "pipeline.first": "Tomcat Exploit"
}

def is_request_blocked(payload):
    """
    Check if the payload contains any blocked malware patterns.
    :param payload: The malicious request payload.
    :return: Tuple (True, malware_name) if blocked; otherwise (False, None).
    """
    for keyword, malware_name in blocked_malware.items():
        if keyword in payload:
            return True, malware_name  # Malware detected, return True with name
    return False, None  # No malware detected

def block_request(malware_name):
    """
    Print a block message with a timestamp instead of allowing the request.
    :param malware_name: The name of the detected malware.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp
    print(f"[{timestamp}] [!] FIREWALL BLOCKED: {malware_name} detected. Request blocked by firewall.")

def main():
    """
    Simulates attack attempts by sending malicious requests.
    - Stops execution if a request is blocked.
    - Counts successful responses.
    """
    target = f"{host}:{port}"  # Corrected formatting of target
    print(f"Beginning test requests to: {target}")
    successful_responses = 0  # Counter for successful responses

    # Loop to send 5 test requests
    for x in range(5):
        # Get current timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Malicious payload designed to trigger a firewall rule
        payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=malicious_code"
        
        # Check if the payload is blocked
        blocked, malware_name = is_request_blocked(payload)
        if blocked:
            print(f"[{timestamp}] [{x + 1}/5] Request blocked. Reason: {malware_name}")
            block_request(malware_name)  # Call function to display block message
            break  # Stop further requests if blocked
        
        print(f"[{timestamp}] [Sending request to {target}]")  # Logging request attempt

        # Create an HTTP connection to the target
        conn = http.client.HTTPConnection(host, port)
        conn.request('POST', '/tomcatwar.jsp', payload, {"Content-Type": "application/x-www-form-urlencoded"})  # Sending POST request

        # Get the server response
        response = conn.getresponse()
        print(f"[{timestamp}] Response status: {response.status}")  # Print HTTP response status
        
        if response.status == 200:
            successful_responses += 1  # Increment successful request count
        elif response.status == 403:
            print(f"[{timestamp}] [!] Server responded with 403 Forbidden. Request was blocked by firewall.")

        print("=============")

    # Print final test summary with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [+] Test completed.")
    print(f"[{timestamp}] [+] Successful responses: {successful_responses}/5")  # Final success count

# Run the script if executed directly
if __name__ == "__main__":
    main()

import http.client  # Import the http.client module for making HTTP requests

# Configuration: Define the target server's host and port
host = "localhost"
port = 8000

# List of blocked keywords and their associated malware names
blocked_malware = {
    "class.module.classLoader": "Remote Code Execution Attack",
    "getRuntime().exec": "Command Injection Attack",
    "pipeline.first": "Tomcat Exploit"
}

def is_request_blocked(payload):
    """
    Check if the payload contains any blocked malware patterns.
    Args:
        payload (str): The data to be sent in the HTTP request.
    Returns:
        tuple: A boolean indicating if the request is blocked, and the malware name if blocked.
    """
    for keyword, malware_name in blocked_malware.items():
        if keyword in payload:
            return True, malware_name  # Request is blocked due to detected malware
    return False, None  # Request is not blocked

def block_request(malware_name):
    """
    Print a message indicating that a request was blocked due to malware detection.
    Args:
        malware_name (str): The name of the detected malware.
    """
    print(f"[!] FIREWALL BLOCKED: {malware_name} detected. Request blocked by firewall.")

def main():
    """
    Main function to conduct the test by sending multiple requests to the target server.
    """
    target = f"{host}:{port}"  # Construct the target address
    print(f"Beginning test requests to: {target}")
    successful_responses = 0  # Counter for successful responses

    for x in range(5):  # Loop to send 5 test requests
        payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=malicious_code"
        # Define a payload containing a known malicious pattern
        
        blocked, malware_name = is_request_blocked(payload)
        if blocked:
            print(f"[{x + 1}/5] Request blocked. Reason: {malware_name}")
            block_request(malware_name)
            break  # Exit the loop if the request is blocked
        
        print(f"[Sending request to {target}")
        conn = http.client.HTTPConnection(target)
        conn.request('POST', '/tomcatwar.jsp', payload, {"Content-Type": "application/x-www-form-urlencoded"})
        response = conn.getresponse()
        print(f"Response status: {response.status}")
        
        if response.status == 200:
            successful_responses += 1  # Increment counter for successful responses
        elif response.status == 403:
            print("[!] Server responded with 403 Forbidden. Request was blocked by firewall.")

        print("=============")

    print("[+] Test completed.")
    print(f"[+] Successful responses: {successful_responses}/5")

if __name__ == "__main__":
    main()  # Execute the main function when the script is run directly

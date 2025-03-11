# Telstra-Cybersecurity_Project


This Python script simulates multiple HTTP POST requests to a target server, aiming to test its vulnerability to specific malware patterns. It connects to a server running on localhost at port 8000 and sends five test requests with a predefined payload. The script checks each response to determine if the server is blocking requests based on known malware signatures.

Script Overview:

Configuration:

host and port define the target server's address.
blocked_malware is a dictionary mapping specific malware patterns (keywords) to their descriptive names.
Function Definitions:

is_request_blocked(payload): Iterates through blocked_malware items to check if the payload contains any blocked keywords. Returns a tuple indicating whether the request is blocked and, if so, the associated malware name.
block_request(malware_name): Prints a message indicating that a request was blocked due to the specified malware detection.
main(): Coordinates the testing process by:
Constructing the target address.
Iterating five times to send test requests.
For each iteration:
Defines a payload containing a known malicious pattern.
Checks if the request should be blocked based on the payload.
If blocked, prints a message and breaks out of the loop.
If not blocked, sends an HTTP POST request to the target server with the payload.
Receives and evaluates the server's response, counting successful (200 OK) responses.
Summarizes the test results after completion.
Execution:

The script's main() function is executed when the script is run directly.



Key Points:

Malware Detection: The script identifies specific patterns in the payload that correspond to known attack vectors. If a match is found, the request is blocked, and a corresponding message is displayed.
Testing Process: It sends five test requests to the target server, each containing a payload with a malicious pattern. The server's responses are evaluated to determine if the requests are blocked.
Response Handling: The script checks for successful (200 OK) and forbidden (403 Forbidden) responses, providing feedback on the server's security measures.
Suggestions for Improvement:

Enhance Payload Variability: Introduce a range of payloads with diverse attack patterns to comprehensively assess the server's vulnerability.
Implement Logging: Utilize a logging framework to record test results and any anomalies for further analysis.
Handle Exceptions: Add error handling to manage potential exceptions during HTTP requests, such as connection errors or timeouts.
Parameterize Configuration: Allow the host, port, and other settings to be specified via command-line arguments or a configuration file for greater flexibility.
Utilize Secure Connections: Consider using HTTPS connections to test the server's handling of secure traffic, especially if the server supports SSL/TLS.

Objective

The Telstra Firewall Project is a hands-on learning initiative developed by Telstra's Security Operations Center to provide practical experience in the role of a Security Analyst. The project's objectives include:

	Triage the zero-day vulnerability malware attack CVE-2022-22965, known as Spring4Shell, and identify the most affected teams.

	Analyze malware data and information.

	Develop and implement a new firewall rule using Python to mitigate the malware's impact.

	Draft an incident post-mortem report detailing the malware attack


 Task 1: Email to Impacted Team

 <img width="842" alt="Screenshot 2025-03-18 at 10 06 59 AM" src="https://github.com/user-attachments/assets/c8e6e223-4a7e-47da-b3c5-595e2ce84d13" />

 	Ref 1: Email send to team that had critical severity impact


  ************************************************************************************************


  (Technical) Mitigate the malware attack = 
  Ref 3: Python code to implement firewall rule


As part of my participation in the Telstra Virtual Experience Program with Forage, I developed a Python-based firewall rule to mitigate the Spring4Shell vulnerability (CVE-2022-22965) affecting Telstra's nbn services. This vulnerability allows remote code execution (RCE) in Spring MVC or Spring WebFlux applications running on JDK 9+ and deployed on Apache Tomcat as WAR files. 
GITHUB

To address this, I created a rule within the firewall_server.py script to block:

Incoming traffic to the client request path /tomcatwar.jsp.
Requests containing patterns identified in the Spring4Shell exploit payload, as detailed in the proof of concept here:
This approach effectively reduces the risk of exploitation by filtering out malicious requests targeting the vulnerability
https://github.com/craig/SpringCore0day/blob/main/exp.py

	# www.theforage.com - Telstra Cyber Task 3
	# Model Work Example
	# Firewall Server Handler

	from http.server import BaseHTTPRequestHandler, HTTPServer
	
	host = "localhost"
	port = 8000
	
	def block_request(self):
	    self.send_error(403, "Request blocked due to firewall")
	
	def handle_request(self):
	    # List of bad headers from the proof of concept payload
	    bad_headers = {
	        "suffix": "%>//",
	        "c1": "Runtime",
	        "c2": "<%",
	        "DNT": "1",
	        "Content-Type": "application/x-www-form-urlencoded",
	    }
	
	    bad_header_keys = bad_headers.keys()
	
	    # If a request is on the Spring Framework path
	    if self.path == "/tomcatwar.jsp":
	        # Iterate through bad headers
	        for bad_header_key in bad_header_keys:
	            # If we find a bad header that matches the malicious payload
	            if bad_header_key in self.headers and self.headers[bad_header_key] == bad_headers[bad_header_key]:
	                # Block request and throw 403 error
	                return block_request(self)
	
	    # Return successful response
	    self.send_response(200)
	    self.send_header("content-type", "application/json")
	    self.end_headers()
	
	    self.wfile.write({ "success": True })
	
	class ServerHandler(BaseHTTPRequestHandler):
	    def do_GET(self):
	        handle_request(self)
	
	    def do_POST(self):
	        handle_request(self)
	
	
	if __name__ == "__main__":        
	    server = HTTPServer((host, port), ServerHandler)
	    print("[+] Firewall Server")
	    print("[+] HTTP Web Server running on: %s:%s" % (host, port))
	
	    try:
	        server.serve_forever()
	    except KeyboardInterrupt:
	        pass
	
	    server.server_close()
	    print("[+] Server terminated. Exiting...")
	    exit(0)

    





  



  Firewall Rule

[T4 - Model Answer.pdf](https://github.com/user-attachments/files/19324453/T4.-.Model.Answer.pdf)




    ********************************************************************************************

    
    Incident Postmortem: Firewall and Python Payload Malware Attack

      1. Summary
      On March 20, 2022, at 03:21 UTC, a security incident was detected involving an attempted Remote Code Execution (RCE) attack on a web application. The attack               exploited vulnerabilities in the Tomcat server to execute unauthorized commands. The incident was flagged by the firewall's malware detection system, which                identified malicious payload patterns.

    Response Teams:

    Network Administrators
    Cybersecurity Analysts
    Severity: Critical (Potential system compromise)

    2. Impact
    The attack attempted to:
    ✅ Upload and execute a malicious JSP shell via an RCE exploit.
    ✅ Gain unauthorized access to system resources.
    ✅ Execute arbitrary commands and escalate privileges.

    Although the firewall successfully blocked the attack, repeated attempts caused:
    ⚠ Temporary service degradation
    ⚠ Increased CPU load due to continuous request filtering

    🛑 No data exfiltration or unauthorized access was confirmed. However, the attack exposed weaknesses in system monitoring and response mechanisms.

    3. Detection
    The firewall’s Intrusion Detection System (IDS) flagged multiple suspicious requests containing malicious payloads, specifically targeting:
    🔎 Parameter: class.module.classLoader.resources.context.parent.pipeline.first.pattern

    Security logs revealed multiple failed breach attempts before the attack was mitigated.

    4. Root Cause
    📌 Unpatched vulnerability in the Tomcat web server allowed exploitation attempts.
    📌 Attack script targeted known weaknesses, injecting malicious payloads to execute commands.
    📌 Inadequate logging and alerting delayed immediate detection of attack severity.

    5. Resolution
    ✔ Firewall successfully blocked the attack, preventing execution of malicious commands.
    ✔ Enhanced firewall rules and detection mechanisms.
    ✔ Patched the affected application server to address known vulnerabilities.
    ✔ Reviewed system logs to confirm no successful breaches.
    ✔ Implemented additional security measures, including:

    Enhanced monitoring
    Rate-limiting of suspicious requests
    6. Action Items
    🔹 Immediate Actions:
    1️⃣ Patch Management: Ensure all application servers and dependencies are up-to-date.
    2️⃣ Firewall Rule Optimization: Improve detection logic for emerging threats.
    3️⃣ Monitoring Enhancement: Deploy advanced security monitoring solutions with real-time alerting.
    
    🔹 Short-Term Actions:
    4️⃣ Incident Response Training: Train IT teams for faster security alert responses.
    5️⃣ Penetration Testing: Conduct regular security audits to proactively identify vulnerabilities.

    🔹 Long-Term Actions:
    6️⃣ Logging Improvements: Implement granular logging for extended threat analysis.
    
    7. Conclusion
    This incident underscores the importance of:
    ✔ Strong firewall configurations
    ✔ Proactive security strategies
    ✔ Continuous monitoring and patch management
    
    Although the attack was successfully mitigated, critical improvements are required in monitoring, patch management, and incident response. Moving forward, enhanced security measures will be implemented to fortify defenses against future threats.



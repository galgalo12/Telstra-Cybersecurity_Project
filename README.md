               # Telstra-Cybersecurity_Project 



                 Responding to a malware attack 


    1 - Here is the background information on your task
    ********************************************

    You are an information security analyst in the Security Operations Centre. A common task and responsibility of information security analysts in the SOC is to respond       to triage incoming threats and respond appropriately, by notifying the correct team depending on the severity of the threat. It’s important to be able to communicate       the severity of the incident to the right person so that the organisation can come together in times of attack.

    The firewall logs & list of infrastructure has been provided and attached here, which shows critical services that run the Spring Framework and need to be online /         uninterrupted. A list of teams has also been provided, which depending on the severity of the threat, must be contacted.
    It’s important to note that the service is down and functionality is impaired due to the malware attack.

    2 - Here is your task
    ********************************

    Your task is to triage the current malware threat and figure out which infrastructure is affected.
    First, find out which key infrastructure is currently under attack. Note the priority of the affected infrastructure to the company - this will determine who is the        respective team to notify.
    After, draft an email to the respective team alerting them of the current attack so that they can begin an incident response. Make sure to include the timestamp of         when the incident occurred. Make it concise and contextual.
    The purpose of this email is to ensure the respective team is aware of the ongoing incident and to be prepared for mitigation advice.!

    Resources to help you with the task
    ****************************************************

    https://www.cisa.gov/news-events/alerts/2022/04/01/spring-releases-security-updates-addressing-spring4shell-and-spring
    

    https://spring.io/security/cve-2022-22965

    ********************************************************************************************

    
Incident Postmortem: Firewall and Python Payload Malware Attack
1. Summary
On March 20, 2022, at 03:21 UTC, a security incident was detected involving an attempted Remote Code Execution (RCE) attack on a web application. The attack exploited vulnerabilities in the Tomcat server to execute unauthorized commands. The incident was flagged by the firewall's malware detection system, which identified malicious payload patterns.

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

Prepared by: [Your Team Name]
Date: [Report Date]

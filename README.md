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



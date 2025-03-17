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


    Incident Postmortem: Spring4Shell Malware Attack

********************************************************************************************
    Incident Overview
    
    On March 20, 2022, at 3:16:34 UTC, a malware attack targeted a vulnerability in Spring applications known as CVE-2022-22965 (Spring4Shell). The attack was mitigated        approximately two hours later through the implementation of a firewall rule. The Security and Network Teams collaborated effectively to address the incident. The           severity of the attack is classified as High due to risks of data breaches, system compromise, and service disruptions.

    Timeline of Events

    Time (UTC)	Event Description
    03:16:34	Initial detection of suspicious activity targeting /tomcatwar.jsp with malicious POST requests.
    03:30:00	Firewall rule implemented to block malicious requests based on specific headers and methods.
    05:16:34	Monitoring indicates a significant decrease in suspicious traffic, confirming mitigation success.


    Root Cause Analysis
    The attack exploited the Spring4Shell vulnerability (CVE-2022-22965), which allows attackers to execute arbitrary code on vulnerable servers via specially crafted          requests. The immediate cause was the absence of a firewall rule to filter out malicious requests targeting specific endpoints with exploitative patterns.

    Impact Assessment
    ********************************************************
    Data Breach: No confirmed unauthorized access to sensitive data was detected.
    System Compromise: No evidence of complete system takeover was found.
    Service Disruption: No significant service interruptions occurred during the incident.
    
    Detection and Response
    ********************************
    The incident was identified through analysis of firewall logs, which revealed an increase in suspicious requests targeting the /tomcatwar.jsp endpoint using POST           methods with potentially malicious headers. In response, a firewall rule was promptly implemented to block requests with specific characteristics, leading to a             significant decrease in suspicious traffic.

    Corrective and Preventive Actions
    Immediate Actions:

    Investigate potential compromises across affected systems.
    Update all Spring applications to versions that address the Spring4Shell vulnerability (CVE-2022-22965).
    
    Short-Term Actions:

    Review and update firewall rules to identify and block potential attack vectors.
    Conduct security awareness training to educate personnel on common attack methods and secure coding practices.
    
    Long-Term Actions:

    Implement continuous monitoring of network traffic and server logs to detect suspicious activity promptly.
    Review and update the incident response plan to ensure a coordinated and efficient response to future security incidents.
    Consider deploying a web application firewall (WAF) for additional protection against application-layer attacks.
    
    Lessons Learned
    This incident underscores the importance of proactive security measures, including regular updates to application frameworks and vigilant monitoring for unusual           activity. Implementing comprehensive firewall rules and maintaining an updated incident response plan are crucial to mitigating similar threats in the future.

    Note: This postmortem is based on available information up to March 16, 2025.








# Threat Hunting Projects

Welcome to my Threat Hunting Projects repository This repository showcases practical scenarios where I've applied threat hunting techniques to identify and mitigate potential security incidents. Each project demonstrates the use of tools and frameworks to simulate real-world threats and effectively respond to them.

## Platforms and Tools Used
- **Windows 10 Virtual Machines (Microsoft Azure):** Simulated enterprise environments for testing and analysis.
- **Endpoint Detection and Response (EDR):** Microsoft Defender for Endpoint (MDE) for identifying and mitigating threats.
- **Kusto Query Language (KQL):** Querying for detailed log analysis.
- **MITRE ATT&CK Framework:** For mapping adversary tactics and techniques.

---

## Projects

### [Threat Hunt Scenario: Data Exfiltration from Employee on PIP](https://github.com/PaulMiguelSec/Threat-Hunting-Projects/blob/main/Threat%20Hunt%20Scenario%3A%20Data%20Exfiltration%20from%20Employee%20on%20PIP.md)
**Scenario Overview:**  
Management suspects that an employee, Scott Firth, who was recently placed on a Performance Improvement Plan (PIP), may be planning to exfiltrate sensitive company data. The employee has administrative access to their device (LAB-WIN10).  

**Objective:**  
The goal of this threat hunt was to detect any attempts to compress and transfer sensitive files to unauthorized locations and mitigate potential risks.

**Key Highlights:**
- Analyzed endpoint logs for signs of file compression and unauthorized transfers.
- Used KQL to detect anomalous behaviors in MDE logs.
- Mapped findings to the MITRE ATT&CK framework for structured reporting.

---

### [Threat Hunt Scenario: Unauthorized TOR Usage](https://github.com/PaulMiguelSec/Threat-Hunting-Projects/blob/main/Threat%20Hunt%20Scenario%3A%20Unauthorized%20TOR%20Usage.md)
**Scenario Overview:**  
Management suspects that some employees may be using TOR browsers to bypass network security controls. Recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there are anonymous reports of employees discussing ways to access restricted sites during work hours.

**Objective:**  
The goal of this threat hunt was to detect any TOR usage, analyze related security incidents, and mitigate potential risks.

**Key Highlights:**
- Investigated network logs to identify connections to TOR nodes.
- Identified suspicious activity using KQL within MDE.
- Alerted management about findings and proposed risk mitigation strategies.

---

## Why These Projects Matter
Threat hunting is a proactive approach to cybersecurity. These scenarios represent my ability to:
- Simulate real-world security incidents.
- Detect and analyze malicious behaviors using industry-standard tools.
- Provide actionable insights and recommendations to improve security postures.

---

## Future Plans
I aim to expand this repository with more scenarios covering:
- Insider threats
- Advanced persistent threats (APTs)
- Lateral movement detection
- Ransomware detection and mitigation

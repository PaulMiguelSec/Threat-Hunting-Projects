# Threat Hunting Scenario: Data Exfiltration from PIP'd Employee

<!--![officeguy](https://github.com/user-attachments/assets/a9391e23-e852-4fce-b1d5-6d7d7ca819e6)-->

![image](https://github.com/user-attachments/assets/dd961da0-e1c6-4258-a0bc-39ef91f47870)


## Platforms and Tools Used
- Windows 10 Virtual Machines (Microsoft Azure)
- Endpoint Detection and Response (EDR): Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework

## 1. Scenario Overview

Management suspects that an employee, Scott Firth, who was recently placed on a performance improvement plan (PIP), may be planning to exfiltrate sensitive company data. The employee has administrative access to their device (`LAB-WIN10`). The goal of this threat hunt is to detect any attempts to compress and transfer sensitive files to unauthorized locations and to mitigate potential risks.

### Hypothesis
Scott Firth is an administrator on his device and might try to archive/compress sensitive information and exfiltrate it to an external destination.

### MITRE ATT&CK Threat Actor Tactics, Techniques, and Procedures (TTPs)
- [**T1078 - Valid Accounts: Use of valid administrative credentials to bypass restrictions**](https://attack.mitre.org/techniques/T1078/)
- [**T1560.001 - Archive Collected Data: Archive via Utility**](https://attack.mitre.org/techniques/T1560/001/)
- [**T1059.001 - Command and Scripting Interpreter: PowerShell**](https://attack.mitre.org/techniques/T1059/001/)
- [**T1567.002 - Exfiltration Over Web Service**](https://attack.mitre.org/techniques/T1567/002/)
---

## 2. Data Collection & Analysis

### Data Sources
1. **File Events**: Activity on `.zip`, `.7z`, and `.rar` files.
2. **Process Events**: Signs of suspicious command execution.
3. **Network Events**: Connections to unauthorized external services.

### Data Collection Queries and Findings

#### 1. File Events Analysis
**Query:**
```kql
DeviceFileEvents
| where DeviceName contains "LAB-WIN10"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| order by Timestamp desc
```

![query1b](https://github.com/user-attachments/assets/cd26b853-e2d1-4cee-b4c7-4a4e1f1881f2)


**Findings:**
- A suspicious file `employee-data-20250106071834.zip` was identified, indicating potential data exfiltration.
- **TTPs Identified:** **T1560.001 - Archive via Utility**

#### 2. Process Events Analysis
**Query:**
```kql
let specificTime = datetime(2025-01-06T07:18:46.3955129Z);
let VMName = "LAB-WIN10";
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName contains VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

![query3](https://github.com/user-attachments/assets/f03d3d0e-2088-45fc-aed7-1a7e25fa744a)

**Findings:**
- Detected PowerShell script `exfiltratedata.ps1` installing 7zip and compressing files.
- **TTPs Identified:**
  - **T1059.001 - Command and Scripting Interpreter: PowerShell**
  - **T1560.001 - Archive Collected Data: Archive via Utility**

#### 3. Network Events Analysis
**Query:**
```kql
let specificTime = datetime(2025-01-06T07:18:46.3955129Z);
let VMName = "LAB-WIN10";
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName contains VMName
| order by Timestamp desc
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
```

![query4](https://github.com/user-attachments/assets/ca436dda-25e2-4390-a8b5-28c523d06cb4)

**Findings:**
- Identified connections to Azure Blob storage via HTTPS (e.g., `https://sacyberrange00.blob.core.windows.net`).
- **TTPs Identified:**
  - **T1567.002 - Exfiltration Over Web Service**
  - **T1071.001 - Application Layer Protocol: Web Protocols**

---

## 3. Investigation Timeline

### Chronological Events
1. **File Activity**: Creation of `employee-data-20250106071834.zip` at `2025-01-06T07:18:34Z`.
2. **Process Execution**: PowerShell script `exfiltratedata.ps1` executed, initiating file compression.
3. **Network Connections**: HTTPS connection to Azure Blob storage at `2025-01-06T07:18:46Z`.

---

## 4. Response

### Actions Taken
1. Isolated the endpoint immediately to prevent further unauthorized access or data exfiltration.
2. Blocked unauthorized connections to external cloud storage.
3. Removed PowerShell scripts and other malicious files from the endpoint.
4. Coordinated with management to limit administrative privileges for the user.

---

## 5. Documentation and Recommendations

### Documentation
- Recorded queries, findings, and associated TTPs for future training and audits.

### Recommendations
1. **Restrict Administrative Privileges:**
   - Reduce elevated access for high-risk employees.
   - **TTP Addressed:** **T1078 - Valid Accounts**
2. **Enhance Monitoring:**
   - Implement PowerShell logging for improved detection of suspicious scripts.
   - Create detection rules specifically targeting archiving tools such as `7zip`, `WinRAR`, and `zip` utilities.
   - Develop alerts for large file transfers or unusual file compression activity.
   - Create detection rules to identify unauthorized silent installations by monitoring specific installer flags such as `/S` or `/quiet` in command lines.
   - **TTP Addressed:** **T1059.001 - Command and Scripting Interpreter: PowerShell**
3. **Strengthen Exfiltration Detection:**
   - Tighten controls on unauthorized cloud services and external connections.
   - Enhance monitoring for connections to known file-sharing platforms and cloud storage services.
   - **TTP Addressed:** **T1567.002 - Exfiltration Over Web Service**
4. **Employee-Specific Actions:**
   - Conduct a formal interview with Scott Firth to address the findings and provide an opportunity for explanation.
   - Mandate participation in cybersecurity awareness training to reinforce acceptable use policies.
   - Place Scott Firth under heightened monitoring for a defined period to ensure compliance with company policies.
   - Involve HR to determine whether disciplinary actions or reassignment are necessary based on intent and severity.

---

This report simplifies and highlights the detection and mitigation process for a potential insider threat scenario, showcasing the effectiveness of Microsoft Defender for Endpoint and KQL in investigating and responding to suspected malicious activities.

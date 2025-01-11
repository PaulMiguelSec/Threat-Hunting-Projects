![unauthorisedtorbanner](https://github.com/user-attachments/assets/06d96ea5-4a2e-4c2e-9c20-fefcf403e647)

# Threat Hunt Report: Unauthorized TOR Usage

### [Threat Event Creation](https://github.com/PaulMiguelSec/Threat-Hunting-Projects/blob/main/Threat-Event-Creation/Threat-Event-Unauthorized-TOR-Usage.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Queried the `DeviceFileEvents` Table

Searched for any file that included the string "tor" and was initiated by the employee's user account (`useruser`). The investigation revealed the user downloaded a TOR installer (`tor-browser-windows-x86_64-portable-14.0.4.exe`), which resulted in the creation of various TOR-related files on the desktop. A file named `tor-shopping-list.txt` was created and modified with Notepad on `2025-01-11T03:11:08.6313532Z`.

**MITRE ATT&CK Technique:** [T1070.004 - Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004/)

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "ThreatHunt-Win1"
| where InitiatingProcessAccountName == "useruser"
| where FileName contains "tor"
| order by Timestamp desc 
| project Timestamp, ActionType, FileName, InitiatingProcessFileName, FolderPath
```

![tordevicefilequery](https://github.com/user-attachments/assets/ed18a8d1-e554-4416-990f-c4b390dc05ed)


---

### 2. Queried the `DeviceProcessEvents` Table for TOR Installation

Searched for any `ProcessCommandLine` containing the string "tor-browser-windows-x86_64-portable-14.0.4". Discovered the user executed the TOR Browser Portable Installer from the Downloads folder using a silent installation command (`/S`), which created the TOR Browser application.

**MITRE ATT&CK Technique:** [T1203 - Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "ThreatHunt-Win1"
| where InitiatingProcessAccountName == "useruser"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4"
| order by Timestamp desc 
| project Timestamp, ActionType, ProcessCommandLine, ProcessVersionInfoProductName, ProcessVersionInfoFileDescription, FolderPath, SHA256
```

![tordeviceprocessquery](https://github.com/user-attachments/assets/99bd22ae-bb32-498b-a656-3d266d8cf90c)


---

### 3. Queried the `DeviceProcessEvents` Table for TOR Execution

Searched for any indication that the user opened the TOR browser. Logs confirmed the TOR browser was launched on `2025-01-11T03:04:51.5564106Z`. Several instances of `firefox.exe` (TOR) and `tor.exe` were also created afterwards.

**MITRE ATT&CK Technique:** [T1059.003 - Command and Scripting Interpreter: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "ThreatHunt-Win1"
| where InitiatingProcessAccountName == "useruser"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp, ActionType, ProcessCommandLine, FolderPath, FileName, SHA256
```

![tordeviceprocessquery2](https://github.com/user-attachments/assets/33319a19-174c-4c7c-b7fd-9ce608f98813)


---

### 4. Queried the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any network connections initiated by TOR processes (`tor.exe`, `firefox.exe`) using known TOR ports. On `2025-01-11T03:09:26Z`, `tor.exe` established a connection to `130.61.173.116` on port `9001`.

**MITRE ATT&CK Technique:** [T1090.003 - Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003/)

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "ThreatHunt-Win1"
| where InitiatingProcessAccountName == "useruser"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc 
| project Timestamp, ActionType, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
```

![tordevicenetworkquery](https://github.com/user-attachments/assets/c5a4472f-ce4a-42d3-9e22-2fb1908aabd7)


---

## Chronological Event Timeline

### Event 1: File Download
- **Timestamp:** `2025-01-11T03:02:42.5909811Z`
- **Action:** File renamed
- **Details:** User downloaded `tor-browser-windows-x86_64-portable-14.0.4.exe` to the Downloads folder.
- **Process:** `msedge.exe`
- **Path:** `C:\Users\useruser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe`

### Event 2: TOR Browser Installation
- **Timestamp:** `2025-01-11T03:04:06.903641Z`
- **Action:** Process created
- **Details:** User executed the TOR Browser installer with a silent installation command (`/S`).
- **Command:** `tor-browser-windows-x86_64-portable-14.0.4.exe /S`
- **Path:** `C:\Users\useruser\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe`

### Event 3: TOR Browser Launch
- **Timestamp:** `2025-01-11T03:04:51.5564106Z`
- **Action:** Process created
- **Details:** User launched the TOR Browser.
- **Path:** `C:\Users\useruser\Desktop\Tor Browser`

### Event 4: File Creation
- **Timestamp:** `2025-01-11T03:11:08.6313532Z`
- **Action:** File created
- **Details:** User created `tor-shopping-list.txt` and later modified it using Notepad.
- **Path:** `C:\Users\useruser\Desktop\tor-shopping-list.txt`

### Event 5: Network Connections Established
- **Timestamp:** `2025-01-11T03:09:26Z` (latest logged event)
- **Action:** Connection success
- **Details:** TOR application established a connection to `130.61.173.116` on port `9001`.
- **Additional Connections:**
  - `192.42.116.188` on port `853`
  - `94.130.51.212` on port `9090`

---

## Summary

The investigation confirms that the user downloaded, installed, and actively used the Tor Browser on their system. They executed the installer with a silent command, which initiated the creation of the application and associated files. A file named tor-shopping-list.txt was created and modified, indicating potential personal use. Network logs show that the Tor Browser successfully established multiple connections to remote servers through known Tor ports, including URLs and IPs tied to Tor relay nodes, confirming active use of the Tor network for anonymous traffic routing. The logs consistently support these findings.he Tor Browser’s functionality, including the presence of tor.exe and related processes.

---

## Response Taken

Tor usage was confirmed on endpoint ThreatHunt-Win1 under the user account useruser. The device was promptly isolated from the network to prevent further unauthorized activity. The user's direct manager was notified, and an internal investigation was initiated to understand the intent and scope of Tor usage. Additionally, relevant logs were preserved for further analysis, and a security awareness session has been scheduled for the employee to address the risks associated with unauthorized software usage

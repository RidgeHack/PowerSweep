# PowerSweep
Enumeration tools for both Blue and Red teams any anyone inbetween. 

# 🛡️ PowerSweep Host Audit Toolkit

A curated collection of PowerShell and script-based tools designed for **Blue Team** operations to audit Windows hosts for misconfigurations, vulnerable services, and security posture weaknesses.

---

## 🔍 Overview

This toolkit helps defenders and system administrators:

- Identify vulnerable services and software
- Audit privilege escalation paths
- Detect insecure configurations
- Perform detailed enumeration of local Windows systems
- Support proactive defense and hardening tasks

Whether you're performing a one-time audit or building a continuous monitoring setup, these tools are designed to be modular, extensible, and easy to integrate into existing workflows.

---

## 📂 Contents

| Tool Name             | Description                                                              |
|----------------------|---------------------------------------------------------------------------|
| `Get-VulnServices.ps1` | Enumerates services with unquoted paths, weak permissions, etc.          |
| `Invoke-HostAudit.ps1` | Runs a general security baseline check on the system                     |
| `Check-AdminShares.ps1`| Identifies exposed admin shares and access risks                         |
| `Enum-AutoRuns.ps1`    | Lists auto-start programs and services that may be abused                |
| `Find-WeakPerms.ps1`   | Searches for weak file or folder permissions on sensitive paths          |
| `Audit-LocalUsers.ps1` | Reviews local accounts, groups, and misconfigured privileges             |

*More tools will be added regularly. Contributions welcome!*

---

## ⚙️ Requirements

- Windows PowerShell 5.1 or PowerShell Core (>= 7.0)
- Run with administrative privileges for full audit capability
- Tested on Windows 10/11 and Windows Server 2019+

---

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/windows-host-audit-toolkit.git
   cd windows-host-audit-toolkit

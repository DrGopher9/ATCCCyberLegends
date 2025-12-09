# Systems & Credentials Inventory

**WARNING:** These are the DEFAULT credentials. Change them immediately.

## "Left Side" (Palo Alto Network)
*Protected by Palo Alto Firewall*

| VM Name | OS | IP Address | Default Creds |
| :--- | :--- | :--- | :--- |
| **Palo Alto FW** | PAN-OS 10.2 | `172.20.242.150` (Mgmt) | `admin` / `Changeme123` |
| **Ecom** | Ubuntu 24.04 | `172.20.242.104` | `sysadmin` / `changeme` |
| **Webmail** | **Fedora 42** | `172.20.242.101` | `sysadmin` / `changeme` |
| **Splunk** | Oracle Linux 9 | `172.20.242.20` | `root` / `changemenow`<br>`admin` / `changeme` |
| **Wkst (Linux)** | Ubuntu 24.04 | *Dynamic (DHCP)* | `sysadmin` / `changeme` |

## "Right Side" (Cisco FTD Network)
*Protected by Cisco FTD Firewall*

| VM Name | OS | IP Address | Default Creds |
| :--- | :--- | :--- | :--- |
| **Cisco FTD** | FTD 7.2.9 | `172.20.240.200` (Mgmt) | `admin` / `!Changeme123` |
| **AD / DNS** | Server 2019 | `172.20.240.102` | `administrator` / `Password123` |
| **Web** | Server 2019 | `172.20.240.101` | `administrator` / `Password123` |
| **FTP** | Server 2022 | `172.20.240.104` | `administrator` / `Password123` |
| **Wkst (Win)** | Win 11 24H2 | `172.20.240.100` | `UserOne` / `ChangeMe123`<br>`administrator` / `Password123` |

## Core Router
| VM Name | OS | IP Address | Default Creds |
| :--- | :--- | :--- | :--- |
| **VyOS Router** | VyOS 1.4.3 | *Gateway* | `vyos` / `changeme` |
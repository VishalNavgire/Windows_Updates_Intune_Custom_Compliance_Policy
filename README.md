📘 INTUNE CUSTOM COMPLIANCE: UPDATE READINESS CHECK
===================================================

🔍 PURPOSE:
-----------
This script is designed to be deployed as part of a **Microsoft Intune Custom Compliance Policy**.  
Its primary role is to **proactively detect** whether a Windows device meets specific **health and compliance criteria**, ensuring:

- ✅ Reliable Windows update installations  
- ✅ Effective MDM (Mobile Device Management) operations  
- ✅ Alignment with enterprise security and compliance baselines  

If any of the defined checks fail, the device is marked as **❌ NonCompliant**, enabling enforcement through **Conditional Access**, **alerts**, or **user notifications**.

🎯 GOAL: Improve update reliability 🔁, reduce IT support issues 🛠️, and maintain Windows servicing compliance across your organization 🏢.


🧪 CHECKS PERFORMED:
---------------------

1️⃣ ✅ **Pending Reboot**
   - Detects if a **reboot is required** using registry values tied to update and servicing operations.
   - ❗ Devices requiring a restart will be marked **NonCompliant**.

2️⃣ ✅ **Low Disk Space (C:\ drive)**
   - Checks available free space on the **system drive**.
   - ⚠️ If **≤ 5 GB**, device is marked **NonCompliant** to prevent update failures.

3️⃣ ✅ **Critical Windows Services**
   - Verifies these essential services are **Running & Enabled**:
     - 🛰️ `dmwappushservice` → WAP Push Service *(MDM sync trigger)*
     - 🧩 `intunemanagementextension` → Intune Management Extension *(executes Win32 apps & scripts)*
     - 🔄 `wuauserv` → Windows Update Service *(manages update fetch & install)*
     - 👤 `wlidsvc` → Microsoft Account Sign-In Assistant *(used for device identity in updates)*  
     - `CryptSvc` → *Provides three management services: Catalog Database Service, which confirms the signatures of Windows files and allows new programs to be installed; Protected Root Service, which adds
                      and removes Trusted Root Certification Authority certificates from this computer; and Automatic Root Certificate Update Service, which retrieves root certificates from Windows Update and
                      enable scenarios such as SSL. If this service is stopped, these management services will not function properly. If this service is disabled, any services that explicitly depend on it will
                      fail to start.*
   - ❌ If any are **stopped**, **disabled**, or **missing** → device is **NonCompliant**.

4️⃣ ✅ **Registry Settings for Update Deferral**
   - Checks registry at:  
     `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
   - Ensures the following values:
     - `DeferQualityUpdatesPeriodInDays` = `0` to `7`
     - `PauseQualityUpdates` = `0`
   - ❌ Missing or misconfigured values will trigger **NonCompliance** due to potential update delays.


📤 OUTPUT FORMAT:
-----------------
Script returns a **JSON object** compatible with Intune Custom Compliance policies:

```json
{
  "PendingReboot": true,
  "SystemDriveFreeGB": true,
  "WapPushServiceHealthy": true,
  "IMEHealthy": true,
  "WindowsUpdateServiceHealthy": true,
  "MSAServiceHealthy": true,
  "CryptographicServiceHealthy": true,
  "DeferQualityUpdatesPeriodInDays": 7,
  "PauseQualityUpdates": 0
}

# SIEM Homelab with Splunk

## Overview

Set up a virtual SIEM environment using Splunk to collect and monitor logs from Linux endpoints and Windows Active Directory Infrastructure. This homelab simulates realistic detection scenarios for common attack behaviors across both Windows and Linux environments.

---

## Lab Setup

### Core Infrastructure
1. **Environment**

   * VMware VM running Debian (no desktop environment).
   * Splunk Enterprise installed on the VM as the central SIEM server.
   * Splunk Universal Forwarder installed on the same VM (acting as both “endpoint” and “forwarder,” for simplicity).

2. **Splunk Enterprise Configuration**

   * Enabled Splunk Web UI at `http://<vm-ip>:8000`.
   * Configured Splunk to autostart on boot:

     ```bash
     sudo /opt/splunk/bin/splunk enable boot-start
     sudo systemctl enable splunk
     ```
   * Opened TCP port 9997 in Splunk (Settings → Forwarding and receiving → Configure receiving).

3. **Splunk Universal Forwarder Configuration**

   * Resolved port conflicts by assigning a new management port (`9089`) to the forwarder:

     ```bash
     sudo /opt/splunkforwarder/bin/splunk set splunkd-port 9089
     ```
   * Registered the forwarder with Splunk (port 9997):

     ```bash
     sudo /opt/splunkforwarder/bin/splunk add forward-server <splunk-vm-ip>:9997
     ```
   * Configured the forwarder to autostart on boot:

     ```bash
     sudo /opt/splunkforwarder/bin/splunk disable boot-start
     sudo /opt/splunkforwarder/bin/splunk enable boot-start
     sudo systemctl enable SplunkForwarder
     ```
### Active Directory Expansion
4. **Windows Domain Controller Setup**
   
   * Windows server VM configured as Domain Controller
   * Splunk Universal Forwarder installed and configured on DC
   * Install "Splunk Add-On for Microsoft Windows"
5. **AD Forwarder Configuration**

   * Outputs configured to send to main Splunk server (port 9997)
   * Windows Event Logs (Security, System, Application) forwarded to index=main through:
     ```powershell
     & "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
     ```

---

## Linux Machine Setup

* **Exported SSH Logs for Monitoring**

  * Used journalctl to continuously export SSH logs to a file via systemd service:

    ```bash
    sudo nano /etc/systemd/system/sshlog.service
    ```

    ```ini
    [Unit]
    Description=Export SSH logs to file for Splunk
    After=network.target

    [Service]
    ExecStart=/bin/bash -c 'journalctl -f -u ssh.service >> /var/log/ssh_output.log'
    Restart=always

    [Install]
    WantedBy=multi-user.target
    ```

    ```bash
    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    sudo systemctl enable sshlog.service
    sudo systemctl start sshlog.service
    ```

* **Forwarder Monitoring Setup**

  ```bash
  sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/ssh_output.log
  ```

* **Real-Time Bash Command Logging**

  * Add to `/etc/bash.bashrc`:

    ```bash
    export PROMPT_COMMAND='RET=$?; logger -p local1.debug "CMD [$USER] [$$] [$(whoami)] [$(pwd)]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")"'
    ```

* **Rsyslog Configuration**

  * Create `/etc/rsyslog.d/bash_logging.conf`:

    ```
    local1.*    /var/log/bash.log
    ```
  * Restart rsyslog:

    ```bash
    sudo systemctl restart rsyslog
    ```
  * Monitor with Splunk Forwarder:

    ```bash
    sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/bash.log
    ```

* **File Integrity Monitoring (FIM)**

  * Create `/usr/local/bin/fim_baseline.sh`:

    ```bash
    #!/bin/bash
    sha256sum /etc/passwd ~/.bashrc /etc/sudoers > /var/log/fim_baseline.log
    ```
  * Create `/usr/local/bin/fim_check.sh`:

    ```bash
    #!/bin/bash
    sha256sum -c /var/log/fim_baseline.log 2>&1 | grep -v ': OK' >> /var/log/fim_alerts.log
    ```
  * Make executable:

    ```bash
    sudo chmod +x /usr/local/bin/fim_*.sh
    ```
  * Add cron:

    ```cron
    */10 * * * * /usr/local/bin/fim_check.sh
    ```
  * Forwarder monitors FIM output:

    ```bash
    sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/fim_alerts.log
    ```
## AD Machine Setup

* **Kerberos Auditing**
  
1. Open **Edit Group Policy** on Domain Controller
2. Go to: `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policy Configuration > Account Logon`
4. Configure the following policies:
   - **Audit Kerberos Authentication Service**: Success and Failure
   - **Audit Kerberos Service Ticket Operations**: Success and Failure
5. Run `gpupdate /force`

### Key Event IDs to Monitor
- **4768**: Kerberos TGT requests (normal authentication)
- **4769**: Kerberos service ticket requests (service access)

---

## Screenshots

## Linux-Based Detections

### Brute Force Alert

![Brute Force Search](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Screenshot%202025-06-03%20020014.png)

### Lateral Movement

#### Outbound SSH Detection

![SSH Movement](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Screenshot%202025-06-03%20020055.png)

#### Reverse Shell Detection

![Reverse Shell Cmd](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Screenshot%202025-06-03%20015935.png)

### Suspicious Command Detection

![Suspicious Cmd](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Screenshot%202025-06-03%20020659.png)


### FIM Alert

Just search for:
```spl
index=* source="/var/log/fim_alerts.log" "WARNING"
```

## Active Directory Attack Detection

### Kerberoasting Detection

#### Attack Simulation
![Kerberoast Attack](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Kerberoasting_2.png)

#### Detection Logic
> The key indicator of Kerberoasting is the **authentication type `0x17`**, which represents a service ticket request (TGS-REQ) using RC4 encryption.

![Kerberoast Search](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Kerberoasting_1.png)

#### Result
![Kerberoast Result](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Kerberoasting_3.png)

---

### 🧵 Golden Ticket Detection

#### Attack Simulation
![Golden Ticket Attack](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Golden_attack.png)

#### Detection Logic
- Golden Ticket attacks abuse forged TGTs to request service tickets, typically resulting in **Event ID 4769** (TGS request) **without a corresponding Event ID 4768** (TGT request).
- Comparing normal vs suspicious patterns helps illustrate this:
  
**Legitimate Behavior:**
![Legitimate Golden Ticket Flow](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Golden_legit.png)

**Suspicious Behavior (Missing 4768):**
![Suspicious Golden Ticket Flow](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Golden_not_legit.png)

- We can create a detection by **identifying 4769 events that have no corresponding 4768 within a short time window**.

![Golden Ticket Search Query](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Golden_search.png)

#### Result
> This search isn’t perfect, but it effectively filters out most legitimate activity.

![Golden Ticket Result](https://github.com/johnny-tavares/SIEM-Homelab/blob/master/Images/Golden_Result.png)

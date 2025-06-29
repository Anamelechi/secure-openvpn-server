# 🛡️Secure OpenVPN Server with Device-Specific SSH Key Binding and Emergency SSH Access  
**Enterprise-Grade VPN Solution with Zero-Trust SSH Access Control and Per-Device Cryptographic Isolation with IP-Based Access Control**  

## 📚 Table of Contents  
1. [🛡️ Project Overview](#project-overview)  
2. [🧰 Prerequisites](#prerequisites)  
3. [📡 OpenVPN Server Setup](#openvpn-server-setup)  
4. [🔐 SSH Hardening](#ssh-hardening)  
5. [🚨 Emergency Access System](#emergency-access-system)  
6. [🪟 Windows Client Configuration](#windows-client-configuration)  
7. [🧩 Troubleshooting Guide](#troubleshooting-guide)  
8. [🧯 Fail-Safe Recovery](#fail-safe-recovery)  
9. [🔄 Security Maintenance](#security-maintenance)  


<a name="project-overview"></a>
## 1. Project Overview
This project implements a secure OpenVPN server on Linux with:
- 🔐 **Restricted SSH access** only through VPN connections  
- 🛡️ **Key-based authentication** with password authentication disabled  
- 🚨 **Emergency SSH access** via encrypted master key for failover scenarios  
- 🧱 **Zero-trust network access** model for server administration  
- 🔑 **Each device has a unique cryptographic identity**  
- 🎯 **SSH keys are restricted to specific VPN IP addresses**
- 🛡️ **Prevention of credential sharing across devices**
### 🧰 Key Security Features and Implementations

| 🔧 **Feature** | 🛡️ **Security Benefit** | ⚙️ **Implementation** |
|------------------------------|---------------------------------------------|--------------------------------------------------------|
| 🔐 Each device has a unique cryptographic identity | Prevents credential reuse across compromised devices | Use Easy-RSA or in-house CA to generate unique certs per client |
| 🔑 SSH keys restricted to specific VPN IPs | Blocks access outside assigned VPN tunnel | Use `from="10.8.0.x"` in `authorized_keys` for IP binding |
| 🛡️ Credential sharing prevention | Enforces device-user identity lock | Use unique device certs + IP-bound SSH, disable password auth |
| 🧱 VPN-only SSH | Thwarts direct brute-force internet attacks | Block SSH on public interface, allow only over tun0 via firewall |
| 🚨 Emergency key access | Enables recovery during key loss or outage | Store a master key encrypted with AES-256, accessible offline |
| 💣 Automatic key deletion | Stops post-compromise key retention | Implement lifecycle scripts to auto-delete keys on trigger or TTL |
| 🎭 Port obfuscation | Hides service from port scanners | Run SSH on randomized or uncommon port number |
| 🚫 Fail2Ban protection | Blocks repeated login attempts | Install Fail2Ban with custom jail rules for SSH/VPN services |



<a name="prerequisites"></a>
### 🧰 2. Prerequisites

### 🖥️ Server Requirements
- 🐧 Ubuntu 22.04 LTS  
- 🌐 Static public IP address  
- ⚙️ 2+ CPU cores, 2GB RAM, 20GB storage  
- 🔓 Ports `1194/UDP` (VPN) and `22222/TCP` (SSH) open in firewall  

### 💻 Client Requirements
- 🪟 Windows 10/11  
- 🔄 OpenVPN GUI client  
- 🔐 OpenSSL for Windows  

### 🌐 Network Preparation
1. **📡 Router Configuration:**
   ```bash
   External IP:Port    ->   Internal IP:Port
   1194/UDP            ->   192.168.1.17:1194
   22222/TCP           ->   192.168.1.17:22222
   ```
2. **🧱 Server Firewall Baseline:**
   ```bash
   sudo ufw allow 1194/udp
   sudo ufw allow 22222/tcp
   sudo ufw enable
   ```

<a name="openvpn-server-setup"></a>
## 📡 3. OpenVPN Server Setup  

### 1. Install OpenVPN and Dependencies
```bash
sudo apt update
sudo apt install openvpn easy-rsa openssl
```

### 2. Configure PKI Infrastructure
```bash
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
nano vars  # Set KEY_* variables
source vars
./clean-all
./build-ca
./build-key-server server
./build-key client1
./build-dh
openvpn --genkey --secret ta.key
```

### 3. Server Configuration
`/etc/openvpn/server.conf`:
```ini
port 1194
proto udp
dev tun
server 10.7.0.0 255.255.255.0
topology subnet
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
remote-cert-tls client
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA512
data-ciphers AES-256-GCM
data-ciphers-fallback AES-256-CBC
dh dh.pem
ca ca.crt
cert server.crt
key server.key
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
comp-lzo
verb 4
explicit-exit-notify 1
```
### VPN Server set up can be automated by using the ```install-openvpn.sh``` scripts using the work-flow

```bash
wget https://github.com/Anamelechi/secure-openvpn-server/install-openvpn.sh -O install-openvpn.sh

sudo chmod +x install-openvpn.sh

sudo bash install-openvpn.sh

sudo cp /root/client1.ovpn ~

```

### 4. Enable IP Forwarding
```bash
sudo nano /etc/sysctl.conf
# Uncomment: net.ipv4.ip_forward=1
sudo sysctl -p
```

### 5. 🔑 Key Binding Format  
In `~/.ssh/authorized_keys` or `/etc/ssh/keys/admin/authorized_keys`:

```bash
from="10.7.0.101" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user-device1
from="10.7.0.102" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user-device2
```

### 6. Start and Enable Service
```bash
sudo systemctl start openvpn-server@server.service
sudo systemctl enable openvpn-server@server.service
```

<a name="ssh-hardening"></a>
## 🔐 4. SSH Hardening 

### 1. Configure SSHD
`/etc/ssh/sshd_config`:
```ini
Port 22222
ListenAddress 10.7.0.1
PermitRootLogin no
MaxAuthTries 2
LoginGraceTime 30
AllowUsers *@10.7.0.0/24
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
AllowAgentForwarding no
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
```

### 2. Create Emergency Key Access
```bash
sudo nano /etc/ssh/emergency_keys
# Paste ONLY emergency public key
```

### 3. Local Network Exception
Add to end of `sshd_config`:
```ini
Match Address 192.168.1.*
    AuthorizedKeysFile /etc/ssh/emergency_keys
    PasswordAuthentication no
```

### 4. Apply Changes
```bash
sudo systemctl reload ssh
sudo ufw allow from 10.7.0.0/24 to any port 22222
sudo ufw deny 22222/tcp
```

<a name="emergency-access-system"></a>
## 🚨 5. Emergency Access System  

### Master Key Creation
**On air-gapped machine:**
```bash
ssh-keygen -t ed25519 -f emergency_key -N "Str0ngP@ssphr@se!"
openssl enc -aes-256-cbc -pbkdf2 -in emergency_key -out emergency_key.enc
shred -u emergency_key  # Securely delete unencrypted key
```

### Transfer to Windows
1. Copy `emergency_key.enc` to `C:\EmergencyAccess\Keys\`
2. Set restrictive permissions:
   ```powershell
   icacls "C:\EmergencyAccess\Keys\emergency_key.enc" /inheritance:r
   icacls "C:\EmergencyAccess\Keys\emergency_key.enc" /grant:r "$env:USERNAME:(F)"
   ```

### Decryption Script
`C:\EmergencyAccess\Scripts\Decrypt-EmergencyKey.ps1`:
```powershell
$ErrorActionPreference = "Stop"

# File paths
$encryptedKey = "C:\EmergencyAccess\Keys\emergency_key.enc"
$tempKey = "C:\EmergencyAccess\Keys\temp_key_$((Get-Date).ToString('yyyyMMddHHmmss')).pem"

# Get passphrase securely
$passphrase = Read-Host "Enter emergency passphrase" -AsSecureString
$plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
)

# Decrypt key
& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" enc -d -aes-256-cbc -pbkdf2 -in $encryptedKey -out $tempKey -pass pass:$plainPass

# Clear passphrase from memory
$plainPass = $null
[System.GC]::Collect()

# Verify decryption
if (Test-Path $tempKey) {
    Write-Host "Key decrypted to: $tempKey" -ForegroundColor Green
    Write-Host "Use with: ssh -i `"$tempKey`" youruser@10.8.0.1" -ForegroundColor Cyan
    Write-Host "This key will self-destruct in 10 minutes" -ForegroundColor Yellow
    
    # Schedule automatic deletion
    $scriptBlock = {
        Start-Sleep 600
        Remove-Item -Path $using:tempKey -Force -ErrorAction SilentlyContinue
    }
    Start-Job -ScriptBlock $scriptBlock
}
else {
    Write-Host "Decryption failed!" -ForegroundColor Red
}
```

<a name="windows-client-configuration"></a>
## 🪟 6. Windows Client Configuration 

### 1. Install Required Software
- [OpenVPN GUI](https://openvpn.net/community-downloads/)
- [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)

### 2. Client Configuration File
`client1.ovpn`:
```ini
client
dev tun
proto udp
remote your-server.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA512
verb 3
key-direction 1
route-metric 1

<ca>
-----BEGIN CERTIFICATE-----
[CA content here]
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
[Client certificate]
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN PRIVATE KEY-----
[Client private key]
-----END PRIVATE KEY-----
</key>

<tls-auth>
-----BEGIN OpenVPN Static key V1-----
[TLS auth key]
-----END OpenVPN Static key V1-----
</tls-auth>
```

### 3. Connection Workflow
1. Place `.ovpn` file in `C:\Program Files\OpenVPN\config\`
2. Connect via system tray icon
3. Verify connection:
   ```powershell
   ping 10.7.0.1  # Should respond
   ```

### 4. Emergency Access Procedure
```mermaid
graph LR
A[VPN Failure] --> B[Run Decrypt Script]
B --> C{Enter Passphrase}
C --> D[Generate Temp Key]
D --> E[Connect via SSH]
E --> F[Auto-Delete Key]
```

<a name="troubleshooting-guide"></a>
## 🧩 7. Troubleshooting Guide  

### Common Issues and Solutions
| Issue | Symptoms | Solution |
|-------|----------|----------|
| VPN Connection Timeout | Client can't reach server | 1. Verify port forwarding<br>2. Check `sudo ufw status`<br>3. Test with `nc -ul 1194` |
| SSH Access Denied | "Permission denied" error | 1. Verify key in `emergency_keys`<br>2. Check `sshd -T` output<br>3. Confirm client in 10.7.0.0/24 |
| Certificate Errors | TLS handshake failures | 1. Verify certificate dates<br>2. Check time synchronization<br>3. Rebuild PKI if needed |
| Routing Conflicts | Internet access lost on VPN | 1. Add `route-metric 1` to client config<br>2. Check server push directives |
| Emergency Key Failure | Decryption errors | 1. Verify OpenSSL version match<br>2. Check passphrase correctness<br>3. Validate file integrity with SHA256 |

### Diagnostic Commands
**Server Status:**
```bash
sudo journalctl -u openvpn-server@server.service -n 50 --no-pager
sudo ss -tuln | grep -E '1194|22222'
sudo ufw status verbose
```

**Client Testing:**
```powershell
Test-NetConnection -ComputerName YOUR_SERVER_IP -Port 1194 -UDP
Test-NetConnection -ComputerName 10.7.0.1 -Port 22222
```

<a name="fail-safe-recovery"></a>
## 🧯 8. Fail-Safe Recovery  
### Lockout Recovery Procedure
1. **Physical Access:**
   ```bash
   sudo systemctl stop ssh
   sudo sshd -d -p 2222  # Debug mode on standard port
   ```
2. **KVM/IPMI Access:**
   ```bash
   sudo ufw disable
   sudo systemctl restart ssh --full-restart
   ```
3. **Cloud Console Access:**
   ```bash
   mount -o remount,rw /
   nano /etc/ssh/sshd_config # Revert changes
   systemctl restart ssh
   ```

### Key Rotation Protocol
1. Generate new emergency key pair
2. Update `/etc/ssh/emergency_keys` on server
3. Distribute new encrypted key to clients
4. Revoke old key immediately
5. Verify access with new key
6. Securely wipe old key storage

<a name="security-maintenance"></a>
## 🔄 9. Security Maintenance  

### Quarterly Checklist
1. [ ] Rotate OpenVPN server certificate
2. [ ] Update emergency SSH key
3. [ ] Audit SSH access logs
4. [ ] Review firewall rules
5. [ ] Apply OS security updates
6. [ ] Test backup recovery procedure

### Automated Monitoring Script
`/usr/local/bin/security-audit.sh`:
```bash
#!/bin/bash
# Check unauthorized access attempts
grep 'Invalid user' /var/log/auth.log

# Verify firewall status
ufw status | grep 'Status: active'

# Check VPN connections
openvpn-status /etc/openvpn/openvpn-status.log

# Validate certificate expiration
openssl x509 -in /etc/openvpn/server.crt -noout -dates

# Test emergency key access
echo | ssh -i /etc/ssh/emergency_key -p 22222 user@localhost true
```

### Backup Strategy
1. **Critical Assets:**
   - `/etc/openvpn`
   - `/etc/ssh`
   - `/root/.ssh`
   - Emergency key passphrase
2. **Backup Command:**
   ```bash
   tar -czvf /backups/vpn-config-$(date +%F).tgz /etc/openvpn /etc/ssh
   gpg -c --cipher-algo AES256 /backups/*.tgz  # Encrypt backup
   ```
3. **Storage Locations:**
   - Encrypted cloud storage
   - Air-gapped USB drive
   - Offsite secure facility

## License
MIT License - See [LICENSE](/LICENSE) for details.


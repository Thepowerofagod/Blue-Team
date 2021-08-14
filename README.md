<p align="center">
  <img src="https://user-images.githubusercontent.com/87951795/127995943-229e5bd5-bfc7-4431-a5ee-c16f5a9233b6.gif" alt="animated" />
</p>

# Blue-Team
Cyber defense tools and techniques

<p align="center">
    <img src="https://user-images.githubusercontent.com/87951795/128604224-d694357c-f8e3-4493-a850-d7ae000dff20.png" alt="animated" />
</p>


The Linux security blog about Auditing, Hardening, and Compliance https://linux-audit.com/

## Security Linux distribution
- Network Security Toolkit (NST)
  - https://sourceforge.net/projects/nst/?source=recommended
- Security Onion 
  - https://securityonionsolutions.com/

## Osquery
Some of the tools (open-source and commercial) that utilize Osquery are listed below.
- https://otx.alienvault.com/endpoint-security/welcome  
- https://orbital.amp.cisco.com/help/ 
 
Performant endpoint visibility:
- https://osquery.io/
- https://github.com/teoseller/osquery-attck

Query multiple endpoints from the Kolide Fleet UI
- https://www.kolide.com/
- https://github.com/fleetdm/fleet

## (IDS) Intrusion Detection Systems
NIDS
- https://www.snort.org/
- https://suricata.io/
- https://zeek.org/
- https://openwips-ng.org/
HIDS
- https://www.ossec.net/

## Network Analysis 
Tools for network behavior analysis also called network security monitoring and just general network analysis, the first one is squeal.
- Sguil https://bammv.github.io/sguil/index.html
- Xplico https://www.xplico.org/
- NetworkMiner https://www.netresec.com/?page=NetworkMiner

You can use Web proxies in order to check out certain things.
If you're wanting to see the traffic between your browser and the endpoint web server:
- https://mitmproxy.org/
- https://portswigger.net/burp
- https://owasp.org/www-project-zap/

## (FIM) File Integrity Monitoring
installed on your device or its host base, and it performs the act of validating the integrity of your operating system or and or applications and files by using a verification method between the current file or what it's checking current state and a known good baseline.
This comparison method often involves calculating a known, a cryptographic checksum or hash of the files original baseline and comparing it with the calculated checksum or hash of the current state of 
So, you know, if there's been any changes, if there is any integrity, change or the file attributes can also be used to monitor integrity.
Generally, the act of performing file integrity monitoring is automated and alerts are then propagated
or sent out through to other systems, such as simply via email or through to a full monitoring system SIEM

- Osquery can be used for intrusion detection and it can also be used as a file integrity monitor across platforms Windows, Mac and Linux.
- Ossec which again can be used as a intrusion detection system and more, also has file integrity monitoring and is multiplatform Windows, Mac and Linux.
- Tripwire: https://github.com/Tripwire/tripwire-open-source
- https://eljefe.immunityinc.com/  

- Linux FIMs
  - https://linux-audit.com/monitoring-linux-file-access-changes-and-modifications/
  - Afick
  - AIDE
  - Osiris
  - Samhain

## (SIEM) Security Information and Event Management
We need to consider how all the information is gathered from all of this detection capability so it can possibly be useful in some way.
But essentially they are all basically a hub where all data comes back to. Log collection, log analysis, event correlation replication, log monitoring, real time alerting, reporting, file integrity monitoring and dashboards that people look at.
- Splunk Enterprise
- AlienVault Open Source SIEM (OSSIM) (Free version available) https://cybersecurity.att.com/products/ossim
- EMC RSA Security Analytics
- HP ArcSight Enterprice Security Manager (ESM)
- IBM Security QRadar SIEM
- LogRhythm Security Intelligence Platform
- McAfee Enterprice Security Manager 
- SolarWinds Log & Event Manager


## Network Isolation
<p align="center">
  <img src="https://user-images.githubusercontent.com/87951795/128722827-340adba9-2709-4ed7-9c38-02dfdac285ad.png" alt="animated" />
</p>

-dd-wrt.com
-pfSense

Keep IOT divices on separate fisical logical or wifi network
switches have what is called isolated collision domains which is a fancy way to say that you can sniff the traffic on the network with a switch because traffic only gets forwarded to the correct physical Lamport based on the mac address.
So the first thing to consider is having separate routable networks for different devices of different levels of trust. this could be implemented via your router, firewall, switch and wifi access point.
- 192.168.1.0/24
- 192.168.2.0/24
- 192.168.3.0/24
- 192.168.4.0/24
You could as an example in this connect this directly via a ethernet cable physically into your router and or firewall depending on what it is you're using and assign it its own network like we have here
VLAN:
Another option of these villans that you can see here villans virtual LANs. 1These are commonly used to isolate networks villans are the logical separation of networks instead of physical. And they use tags included in the packets that are sent between the devices on the network in order to determine that they are separate

Wi-Fi you will need a router and or access point that supports something called a ip isolation and it will need to support multiple SSIDs on the same access point.

- Secure Router
  - Disable WPS
  - Disable UPnp
  - Disable DMZ
  - Disable any Port Forwarding
  - Update Router’s Firmware
  - Use a complex WPA2 personal password whit CCMP(AES) or CBC-MAC algorithm
  - Use Not common network name (SSID)
  - Change routers login password
  - Enabling AP Isolation
  - Having separate Wi-Fi networks for devices of a different trust levels. SSID1, SSID2...

## Vulnerability Scanner
- Nessus: https://www.tenable.com/products/nessus/nessus-essentials
- OpenVAS: 
    - Option 1: Install from Kali/OpenVAS repositories:
      - https://websiteforstudents.com/how-to-install-and-configure-openvas-on-ubuntu-18-04-16-04/
      - https://www.agix.com.au/installing-openvas-on-kali-in-2020/
    - Option 2: Install from Source:
      - https://github.com/greenbone/openvas-scanner/blob/master/INSTALL.md
    - Option 3: Run from Docker (Preferred):
      - https://github.com/mikesplain/openvas-docker
      - https://hub.docker.com/r/mikesplain/openvas/dockerfile
```
apt install docker.io
docker run -d -p 443:443 --name openvas mikesplain/openvas
Navigate to https://127.0.0.1 
User: Admin, Password: Admin
```
## Application and Execution Control
All methods to preven the execution of malicious code on the endpoint. Things like Access Control ACLS, application white lists, anti executionsoftware AV or end point protection application controls, UAC, digital signatures, reputation systems, parental controls, software restriction policies and so on. Mostly use a form of application white listing to ensure the only specifically selected objects or programs and software libraries are executed. Use white listing on host and use a VM to be more dynamic.
- Windows
    - Application control
      -  Software Restriction Policies
      -  AppLocker
      -  Appguard
      -  VoodooShield
      -  NoVirusThanks
    - Exploitation Prevention
      - EMET
      - MALWAREBYTES MBAE
      - PALOALTO TRAPS
      - HITMAN PRO ALERT (Best)
- Mac
    - https://github.com/google/santa
    - More from Google: https://github.com/google/macops
    - More Apps: https://objective-see.com
- Linux (Security frameworks)
  - AppArmor
  - SElinux
  - Grsecurity

## Security Through Isolation and Compartmentalization

Physical Security Domains
Physical Separation provides the highest level of security and privacy.
could be that you have one lock down physical machine or laptop,
and the operating system and everything in it
is configured in a certain way that that gives you high security.
And you have another physical machine or laptop,
and that is for general use.

Virtual Security Domains - Platform Virtualization software
So if you have a virtual machine guest operating system,
so say for example Debian,
if this was compromised and your host operating system, say Windows,
then that would be difficult to access,
it would be difficult to get from Debian to Windows through the Hypervisor.
The Hypervisor would need to be exploitable,
or it would have to be poorly configured in some way
like you’ve allowed file sharing or something like that in order,
so the exploit from the Debian to the Windows environment can be done.

To create separate domains you could do things like dual booting,
you can use Platform virtualisation software and hypervisors,
the likes of VMware, Virtualbox,
Vagrant, Hyper-V, VPC.
There’s also Kernel Virtual Machine,
there’s Jails or BSD Jails,
Zones, Linux Containers, Docker.
You can also have hidden operating systems,
VeraCrypt and TrueCrypt provide that functionality.
You can have separate hard drive partitions
that are encrypted and hidden.
You can have things like Sandboxes.
You can have portable apps.
You can have non-persistent operating systems like Tails,
Knoppix, Puppy Linux,
JonDo Live, Tiny Core Linux.
You can have bootable USBs.
You can have operating systems
that are dedicated to Isolation/Separation like Qubes,

## Sandboxing
- Windows 
- Mac
- Linux
- Use Firefox in custom VM whit Apparmor and Firejail (amnesic or roll back the snapshot)


## Unique Hardware Identifiers

MAC and How to change the Mac Address
If they know the unique MAC, that can be potentially traced back to you through the purchasing of that device.
08:00:27:2e:5b:59 = [08:00:27] Manufacture identifier [2e:5b:59] Unique identifier
Virtual machines hide your real MAC and also allow for the setting of the MAC address. You need to change the virtual MAC through the VM settings frequently.
Tails use MAC Changers as default. But do check to make sure they don’t show the real MAC.
You could anonymously purchase a whole bunch of cheap USB network adaptors and use a MAC changer in combination to mitigate the risk.This would be the best way of MAC mitigation
- Windows
ipconfig look for Physical Address
  - https://technitium.com/tmac/
- Linux
ficonfig look for HWaddr or ether. ip addr or ip a look for link/ether
  - https://linuxconfig.org/change-mac-address-with-macchanger-linux-command
```
sudo apt install macchanger
sudo ifconfig [interface] down
sudo macchanger -r [interface]
sudo ifconfig [interface] up
```
- Mac
ficonfig look for HWaddr or ether
```
sudo ifconfig [interface] ether aa:aa:aa:aa:aa:aa
```
  - https://www.macupdate.com/app/mac/25729/macdaddyx
  - https://wifispoof.com/


View CPU information
This will show you what information is available in your CPU, there shouldn’t be anything unique if you have a modern processor.
- Windows
  - https://www.cpuid.com/softwares/cpu-z.html
- Linux
  - https://launchpad.net/i-nex
- Mac
  - https://software.intel.com/content/www/us/en/develop/download/download-maccpuid.html

Motherboards 
often, but not always, contain unique identifiers in the system management BiOS,
Use Dmidecode on Mac, Windows or Linux.

Hard Drive 
serial numbers and unique IDs as these can exist as well.
- Windows
```
wmic diskdrive get serialnumber
```
- Linux
```
sudo apt install lshw
sudo lshw -class disk 
```
- Mac
```
system_profiler SPSerialATADataType
```

change the hardware serial IDs.
- Windows
  - VolumeID (sysinternals) 
  - Chameleon
The next mitigation is to have anonymously purchased the devices that you use.
Another strong mitigation is using virtual machines Virtual machines have different physical machine IDs and there is no traceable connection to the real physical machine’s unique hardware IDs So when in a virtual machine, you don’t need to worry about these hardware serial numbers.

Portableapps
- https://portableapps.com/
These can be used with Linux, Unix, and BSD via Wine,
and Mac OSX via Crossover, Wineskin, Winebottle, and PlayOnMac.
The application could be placed on a physically secure device, like an encrypted USB.

## Firewall
Many firewalls are configured to simply drop incoming packets. Nmap sends a TCP SYN request, and receives nothing back. This indicates that the port is being protected by a firewall and thus the port is considered to be filtered.
That said, it is very easy to configure a firewall to respond with a RST TCP packet. For example, in IPtables for Linux, a simple version of the command would be as follows:
```
iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
```
This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

### Host base Firewall
### Network base Firewall

## Anti-Virus and End-Point-Protection
- Comparatives
    - https://www.av-comparatives.org/
    - https://www.av-test.org/
- Windows
    - https://www.bitdefender.com/
    - https://www.kaspersky.es/
    - https://norton.com
    - https://www.malwarebytes.com/
    - Aditional:
       - https://www.hitmanpro.com/
       - https://www.herdprotect.com/
- Mac
    - https://www.bitdefender.com/
    - https://www.kaspersky.es/
    - https://norton.com
    - https://www.malwarebytes.com/
- Linux
    - Linux Security Review 2015: https://www.av-comparatives.org/wp-content/uploads/2015/05/avc_linux_2015_en.pdf
    - Linux malware Wiki: https://en.wikipedia.org/wiki/Linux_malware
    - https://www.rfxn.com/

## Threat Detection and Monitoring
CanaryTokens: https://www.stationx.net/canarytokens/
These canary tokens can alert you if something or someone is trying to look through your personal files on your device, on your laptop, your phone, your tablet, in your email, on your online account and so on.  

Add Email and Description  
Select: DNS/HTTP or Browser Scanner(Show more info)  
Generate Token: Web bugs   
thunderbird > New Email > Insert Image > insert the web bug (change the ending to something like image.gif), don´t atach and dont use alternate text.  
Add Value data from the example to the email: https://www.stationx.net/canarytokens/  
Add more traps in the email like email adreses or links  
Add SMTP Token (Trap Emails) to data base.  

OpenCanary
The password is shown in plain text here, which is not ideal, but you can set up any email account to do this and then forward it to the actual email address that you normally use.
- https://github.com/thinkst/opencanary
- https://docs.opencanary.org/en/latest/index.html
- https://canary.tools/

Artillery - Binary Defense
- https://www.binarydefense.com/
- https://github.com/BinaryDefense/artillery

HoneyDrive
- https://sourceforge.net/projects/honeydrive/
- https://bruteforce.gr/honeydrive/

## Firefox Extensions
- HTTPS Everywhere
- uBlock Origin
  - I am an advanced user
     - Block 3rd-party frames
  - Prevent WebRTC from leaking local IP addresses
  - Add more Filters 
- uMatrix
- No-script

## Encryption
- Full Disk Encryption
  - Windows
     - https://www.veracrypt.fr/en/Home.html
     - BitLocker
  - Mac
    - Filevault2
  - Linux
    - Dm-crypt and LUKS
      - https://github.com/cornelinux/yubikey-luks
    - Encrypting the boot partition with Grub2

- Containers, Partition, USBs
  - https://www.veracrypt.fr/en/Home.html

- Files
  - (Windows, Linux) https://peazip.github.io/
  - (Mac) https://www.keka.io/en/
  - https://www.aescrypt.com/
  - GPG : https://gnupg.org/download/
     - Windows : https://www.gpg4win.org/   
     - Mac : https://gpgtools.org/  

## Password Manager
If an attacker is present on your device using a key logger or other sort of malware, they will be able to capture the master password, which would compromise your database optimally. You would want to install this in a virtual machine to provide that extra layer of isolation or in cubes like as a separate VM to just give it that extra isolation. You may even steal the file on an encrypted USB or some other form of physical isolation.
- https://masterpassword.app/
- https://keepass.info/
- https://keepassxc.org/
- https://www.lastpass.com/

This interactive brute force search space calculator
- https://www.grc.com/haystack.htm
- https://lowe.github.io/tryzxcvbn/

## 2FA
Soft Tokens
- https://authy.com/

Hard Tokens
- https://www.yubico.com/
- https://www.nitrokey.com/

## Email
- thunderbird: https://www.thunderbird.net

- Email Aliases (. and +)
  - username@protonmail.com > u.s.e.r.name@protonmail.com > u.s.e.r.name+wedding@protonmail.com
  - johndoe@gmail.com > j.o.h.n.d.o.e@gmail.com > j.o.h.n.d.o.e+youtube@gmail.com

- Temp Mail:  
  - https://www.guerrillamail.com/
  - https://tempmailaddress.com
  - Huge list of other providers - https://gist.github.com/michenriksen/8710649

- Anonymous Email
  - Proton Mail - https://protonmail.com/ 
  - elude - https://elude.in
  - torbox 
  - Riseup
  - mail2tor 
  - More: https://www.reddit.com/r/onions/comments/6krt34/list_of_onion_email_providers/

## Dark Net
Dark Net Search Engines:  
- duckduckgo.com
- NotEvil  
- torch 
- ahmia 

Dark Net Listings:  
- hidden wiki 
- dark.fail - PGP verifies links  
- deep web subredit: https://www.reddit.com/r/deepweb/  
- onions sub reddit - https://www.reddit.com/r/onions/  

Dark Net Others:  
- hidden answers answerstedhctbek.onion  
- dread - reddit http://dreadditevelidot.onion/  
- privacy sub reddit - https://www.reddit.com/r/privacy/  

Fake ID:  
- https://www.elfqrin.com/fakeid.php

XMPP Servers
- https://gist.github.com/dllud/a46d4a555e31dfeff6ad41dcf20729ac

BTC Mixers:
- https://bitcoin-laundry.com/
- https://bitmix.biz/en 
- https://mixtum.io/ 

Crypto Exchange:
- https://www.morphtoken.com/

Core Windows Processes  
Task Manager  
Process Hacker  
Process Explorer  

Sysinternals
https://docs.microsoft.com/en-us/sysinternals/downloads/



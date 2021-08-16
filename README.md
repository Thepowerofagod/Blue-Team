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
- Whonix
  - https://www.whonix.org/
- Qubes OS
  - https://www.qubes-os.org/downloads/
- Tails
  - https://tails.boum.org

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
Dual Boot
There is no real isolation in the file system with dual boot.

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

Type 1 (Faster and More Secure)
You might set up a
Type 1 hypervisor on a server on your network,
or remotely in the cloud to escape
an adversary’s sphere of influence
that host virtual machines for you.
- VMware ESX/ESXi
- Oracle VM Server
- Microsoft HyperV
- XenServer

Type 2
- Virtual Box
- Vmware Player
- Vmware workstation
- Vmware fusion
- Parallels Desktop
- Vagrant
- VPC
- Citrix Desktopplayer

Virtual Appliance - TurnKey Linux
https://www.turnkeylinux.org/

Virtual Machine Weaknesses  
For example, a simple remote access tool running on the host
would only need to take a screenshot
to watch the activity of the guest virtual machine,
or run a key logger which would effectively break
the isolation between them completely.
Maintaining the security of the host operating system
is of paramount importance.   

Also, vice versa to what we’ve just discussed,
a guest VM could compromise the host operating system,
or other VMs due to vulnerabilities and configuration settings.
The hypervisor sandbox or the VM Tools installed
can have security vulnerabilities that could compromise this isolation.  

Virtual machines can leak information, so for example,
traces of your virtual machine’s session could be left
on the local hard drive of the host,
even if it’s a live operating system.  
For example, host operating systems usually use
virtual memory called swapping or paging
which copies parts of the RAM to the hard drive.
This could contain information about the guest’s session,
and it could be left on the host’s hard drive.  
Virtual Machine Hardening   
So one approach to deal with this problem,
of all the unwanted host data, would be to use
whole disk encryption on the host machine.
ENable Encryption on the VM settings to.
Encrypting the operating system itself using more well-known encryption technology such as LUKS, FileVault 2, Bitlocker, and VeraCrypt.

VMs are used by security researches to deliberately isolate malware,
Because of this, advanced malware writers
have designed counter measures that can detect
when their malware is running on a virtual system,
causes the malware to shut down its malicious functionality,
This is great for us,
when using VMs for isolation, and as a security control,
as the malware effectively disables itself,
Some malware uses the virtual machine detection
to then attempt to exploit security holes

Shared networks are also an attack vector.
If the guests and hosts share the same network,
if any of those machines are compromised,
the other machines could be targets for attack.
In most instances, if you are using VirtualBox on your laptop,
the host and guest will share the same network. So for example,
maybe you have a Debian host and a Windows guest,
which have a bridged network adapter.
Windows, the guest is compromised, the Windows VM then attempts an SSL stripping attack.  
Virtual Machine Hardening  
Using a USB network dongle instead of the host network adapter,
as discussed already in the area on physical isolation.
You can place the VM on a separate network to the host
or for virtual isolation via a VLAN.
This is to help mitigate attacks that come from the network,


Features like shared folders, clipboard access
and drag and drop functionality,
all reduce the isolation and allow attack vectors.

Virtual Machine Hardening  
- disable the audio and the microphone
- cover your webcam with tape
- disable shared folders
- disable drag and drop and clipboard,
- don't enable video acceleration, 3D acceleration
- do not enable serial ports.
- If you can, do not install VirtualBox Guest Addition or VMWare Tools or equivalent.
- You want to remove the floppy drive and remove any CD or DVD drives.
- If it's a Live operating system, you want to remove any virtual disks.
- Do not attach USB devices if you can help it, perhaps the network dongle, but nothing else if you can avoid it.
- Disable the USB controller which is enabled by default. (When you disable the USB controller, this requires you setting the pointing device to be a PS/2 mouse so that your mouse will work.)
- Do not enable remote display server,
- do not enable I/O APIC or EFI.
- Enable PAE/NX, NX is in fact a security feature. (System > Processor)
- If you are concerned about someone getting a hold of your device and local forensics, then use non-persistent operating systems like live CDs, live USBs and don't add virtual storage when setting up the virtual machine.
- You can create your own custom live operating system, so you go about installing whatever operating system it is that you want, configuring it in the way that you want, and then you can convert the virtual disk to an ISO and then boot from the ISO as a live CD. https://www.turnkeylinux.org/blog/convert-vm-iso
- You can use VMware snapshots to create non-persistence. after you’ve performed your activities you restore. It is a reasonably good solution for basic non persistence.


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
Sandbox is an isolated environment for running applications or code. It’s a virtual container to keep the contents confined to that container.
A sandbox should be used for high risk applications, such as those that interact directly with untrusted sources like the internet, such as browsers and email clients.
![Screenshot 2021-08-14 at 15 32 22](https://user-images.githubusercontent.com/87951795/129447950-a00fd4a0-ab66-4b1f-a984-55fbe64fc6d8.png)
![Screenshot 2021-08-14 at 15 28 40](https://user-images.githubusercontent.com/87951795/129447952-b47214d5-8d81-46c9-8c73-4e71c5185fc8.png)

Deep Freeze Windows, Mac and Linux
It provides a completely non-restrictive working environment where there is no need to be concerned about system damage or corruption; a simple restart eradicates all changes and ensures that the standard system configuration is available at all times.
- https://www.faronics.com/en-uk/products/deep-freeze/standard

- Windows 
  - Sanboxie-Plus https://sandboxie-plus.com/downloads/
  - https://bufferzonesecurity.com/product/how-it-works/
  - https://www.shadowdefender.com/
- Linux
  - AppArmor is a kind of sandbox. It is a mandatory access control framework for Linux. What AppArmor does is it confines programs according to a set of rules that specify what files a given program can access.
    - https://en.wikipedia.org/wiki/AppArmor
  - Firejail
    - https://firejail.wordpress.com/
    - https://github.com/netblue30/firejail
    - https://sourceforge.net/projects/firejail/
      - firejail --private firefox
  - https://linux.die.net/man/8/sandbox
  - https://igurublog.wordpress.com/downloads/script-sandfox/
  - 
- Mac
  - https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html
  - https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
  - https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles
  - https://github.com/pansen/macos-sandbox-profiles/blob/master/firefox.sb
  - https://github.com/hellais/Buckle-Up
  - https://www.shirt-pocket.com/SuperDuper/SuperDuperDescription.html
  - https://paolozaino.wordpress.com/2015/08/04/how-to-run-your-applications-in-a-mac-os-x-sandbox-to-enhance-security/



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
Firewalls allow and deny traffic based on a set of rules or what's called an access control list.
More advanced firewalls work at the application layer to do deep packet inspection or DPI and a generally dedicated hardware firewalls.

Ingress/Inbound Filtering:
Because of Nat no network traffic can connect in to the network without an explicit port forwarding rule
or demilitarized zone being set up to allow that traffic
So there is little need for a firewall to block inbound traffic.
In most cases on a home network because inbound traffic from real Internet IPs cannot communicate to
private IP addresses on an internal network it's just not possible unless you set up that port forwarding
or that demilitarized zone.
NAT doesn't protect you from not trusted devices on a network that you share.

Egress/Outbound Filtering
Egress filtering a firewall can be used for blocking
outbound connections.
So for example stopping your Windows machine from communicating home to Microsoft or DNS leaks from
a VPN or malware communicating to its command and control server.
Attackers make connections out once they have a foothold on your device using their malware.
Outbound connections from a home network to an Internet IP address is how malware communicates not via inbound.


Many firewalls are configured to simply drop incoming packets. Nmap sends a TCP SYN request, and receives nothing back. This indicates that the port is being protected by a firewall and thus the port is considered to be filtered.
That said, it is very easy to configure a firewall to respond with a RST TCP packet. For example, in IPtables for Linux, a simple version of the command would be as follows:
```
iptables -I INPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset
```
This can make it extremely difficult (if not impossible) to get an accurate reading of the target(s).

For Host or Network based Firewalls. There should be an implicit deny all to external traffic connecting inbound unless it is specifically required.
- General Firewall Rueles Host or Network based
  - All network traffic should be denied unless implicitly allowed.
  - Block IPv6
  - Block UPnP 1900
  - Block IGMP
  - Block any Windows Mac or Linux service that are not being used by you.

- Host base Firewall
  - Windows 
    - Windows Firewall https://www.howtogeek.com/227093/how-to-block-an-application-from-accessing-the-internet-with-windows-firewall/
    - Windows Firewall Control (WFC): https://www.binisoft.org/wfc.php
    - https://tinywall.pados.hu/
    - https://www.glasswire.com/
    - Antivirus base Firewall like Kapersky or BitDefender
  - Linux
    - IPtables: Linux use NET filter sistem as firewall solution iptable is an interface for it.
```
iptables -L

Chain INPUT controls inbound connections enable file share or let people ping this pc.

Chain FORWARD controlling inbound connections that are destined to be forwarded on to another device.
Unless your device has a router or is doing NAT or something special like SSL stripping you won't use 
this forward chain on a laptop or a desktop.

Chain OUTPUT controls outbound connections. If you wanted this laptop to be able to surf the web you might enable port 53, 80 ,443.

chains have default behaviour called default policies. 
Every table starts at the top of its list of rules and goes through each rule until it finds one that
matches if one does not match. It applies the default policy 
They can actually be set to three different options.

Accept: allow connections to come through.
Drop: drop the connection and send no response back to the source
Reject: don't allow the connection and send back a response to inform the source that it has been rejected.

(delete the rules)
iptables -F 

(change chain police)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP



```
- Network base Firewall




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



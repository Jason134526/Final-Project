# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology
The following machines were identified on the network:

- Kali
  - **OS: Kali Linux**
  - **Purpose : Attacking Machine**
  - **IP: 192.168.1.1**
- ELK
  - **OS: Linux**
  - **Purpose: Elasticsearch, Logstash, Kibana**
  - **IP: 192.168.1.100**
- Capstone
  - **OS: Linux**
  - **Purpose: HTTP server**
  - **IP: 192.168.1.105**
- Target 1
  - **OS: Linux**
  - **Purpose: HTTP/Wordpress (victim)**
  - **192.168.1.110**
- Target 2
  - **OS: Linux**
  - **Purpose:**
  - **IP: 192.168.1.115**

### Description of Targets

The target of this attack was: `Target 1` **192.168.1.110**.

Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### HTTP Request Size Monitor

Alert 1 is implemented as follows:

  - **Metric**: http.request.bytes
  
  - **Threshold**: 3500 / 1 min
  
  - **Vulnerability Mitigated**: By monitoring / controlling http requests by byte size we can mitigate against DDOS attacks. 
  
  - **Reliability**: High reliability for this alert has a low possibility of creating false positives, we can be assured that this alert is reliable. 

#### Excessive HTTP Errors
Alert 2 is implemented as follows:

  - **Metric**: http.response.status_code > 400
  - **Threshold**: 5 errors in last 5 minutes
  - **Vulnerability Mitigated**: With this alert, we can mitigate brute force attacks by alerting of multiple error responses within the last 5 minutes which may perhaps be an attempt to access the server, with multiple failed attempts.
  - **Reliability**: Medium reliability,
  This alert may help find potential attacks but does have a slight chance of generating false positives in the case of human error or possible network issues unrelated to an attack.

#### CPU Usage Monitor 
Alert 3 is implemented as follows:

- **Metric**:system.process.cpu.total.pct

- **Threshold**: 0.5 in last 5 minutes 

- **Vulnerability Mitigated**: Monitoring CPU usage for unusual spikes can possibly indicate that there is a malicious file or virus attacking the system and mitigate risk of total compromise by integrating systems like a Host IPS (Intrusion Prevention System)  that can actively monitor and filter out traffic containing malicious code.
- **Reliability**: This alert can be useful, however It has low reliability due to the fact that CPU usage does not only spike during attacks, but in many other circumstances from time to time.


### Suggestions for Going Further (Optional)

- Each alert above pertains to a specific vulnerability/exploit. Recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks. It is not necessary to explain _how_ to implement each patch.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats, identified by the alerts above. In addition to watching for occurrences of such threats, the network should be hardened against them. The Blue Team suggests that IT implement the fixes below to protect the network:


- Vulnerability 1 HTTP Request Size - DDoS
  - **Patch**: Implement firewalls to the network and Install snort using the following commands in terminal
	  + apt-get install snort
	  + apt-get install libdnet && apt-get install build-essential &&apt-get install bison flex && apt-get install libpcap-dev && apt-get install libpcre3-dev && apt-get install libnet1-dev && apt-get install zlib1g-dev && apt-get install libnetfilter-queue-dev # daq: nfq && apt-get install libmnl-dev && apt-get install libnfnetlink-dev && apt-get install libnetfilter_queue-dev
	  
	  
  - **Why It Works**: A firewall can restrict all traffic and only allow connections that are necessary and being used. Snort will actively monitor and block any unwanted traffic using the rules within snort.
  
- Vulnerability 2 Excessive HTTP Errors (Brute Force)

  - **Patch**: install fail2ban & reconfigure pwquality.conf.
  
	- sudo apt-get install fail2ban
	- sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
	- sudo nano /etc/fail2ban/jail.local [to edit configs]
	
  	- Require stronger password policies within the user account settings which can be found in the following paths. 

  				Windows : /etc/security/pwquality.conf
  				Linux : /etc/security/pwquality.conf
  	
  	-We can also disable ssh entirely OR create an ssh key to add an extra layer of security.			
 	

- **Why It Works**: Fail2ban is an IPS that can be integrated with a firewall or a packet control system on the server and is commonly used to block connections after a number of failed tries which can be configured to the users preferences. This will prevent unauthorized users from guessing or brute forcing passwords with little to no effort, needing more resources to potentially gain access may deter attackers from making an attempt at all.
  
- Vulnerability 3 CPU usage (Spike from malware/virus)
  - **Patch**: Install an up-to date Anti-Virus software along with snort and run regular scans for malware and viruses.
  - **Why It Works**: While snort blocks unwanted traffic based on a set of rules, regular scans with an up to date anti-virus software can mitigate against threats that may have infiltrated the system inadvertently by a user downloading malware in the form of a PUP/PUA/Grayware.

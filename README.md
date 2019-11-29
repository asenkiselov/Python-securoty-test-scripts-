# Python-securoty-test-scripts
These scripts allow testing your network, web-sites or Windows,Mac and Linux vulnerabilities.
Anyone who wants to use ARP spoof, packet sniffer , DNS spoof,keylogger,malware backdoor and etc.

ARP_spoofer:
Don't forget packet forward through your linux PC.
To make the change permanent insert or edit the following line in edit /etc/sysctl.conf:
net.ipv4.ip_forward = 1
or alternatively:

echo 1 > /proc/sys/net/ipv4/ip_forward

DNS_spoofer:
Capture network trafic and redirect dns request on tha victim machne to dns to different host.
Firs of all you must activate arp_spoofer script, after that execute next commands
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 
(to test your script on your local PC,chnge the network queue to your local iptables. 
sudo iptables -I INPUT -j NFQUEUE --queue-num 0 and 
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0  )
To make reset: sudo iptables --flush
Installation
apt-get install build-essential python-dev libnetfilter-queue-dev
sudo pip install requirements.txt

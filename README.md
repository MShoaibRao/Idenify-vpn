# Idenify-vpn
Step-1:SetUp
	install pkgs by cmds:
		sudo pip install pyfiglet
		sudo pip install scapy
		sudo pip install ipwhois
	

Step-2:Working
	1.Provide Internet to ubuntu laptop by ethernet.
	2.open hotspot in in ubuntu machine
	3.connect mobile (android/iphone/desktop) to this hotspot connection
	4.add interface in the script file last line(comment added) and then connect vpn
	5.run the script by with sudo 
		sudo pyhton3 vpn_trace.py
	
	6.Now Script is filttering the vpn ip if connected. and add the result (shortlisted ips) in 
	tracd_vpn_ips1.txt file. with their hostname ans ASNs too.



There are different techniqes that we use to idenify VPN  ips manully are applied in this script.
Script is currently being used by Decoding team.and giving 95%+ acuuracy.
A high level Working chart is also attached.
This script is continuouly Updating to sure 100%

#!/usr/bin/python3

import nmap

scanner = nmap.PortScanner()

print("Welcome to the nmap scanner tool.")
print("-"*20)

ip_addr = input("Please enter the IP address you want to scan: ")

print("Selected IP: ", ip_addr)
type(ip_addr)

scan_type = input("""\nChoose the type of scan you want to run
1.SYN ACK Scan
2.UDP Scan
3.Comprehensive Scan
:""")

print("Selected option --> ", scan_type )


## Types of scan

if scan_type == "1":
	print("Nmap version: ", scanner.nmap_version())
	scanner.scan(ip_addr, "1-1337", "-v -sS")
	print(scanner.scaninfo())

	## Check IP status
	print("IP Status: ", scanner[ip_addr].state())

	## Use all protocols
	print(scanner[ip_addr].all_protocols())
	print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
 
elif scan_type == "2":
	pass
elif scan_type == "3":
	pass

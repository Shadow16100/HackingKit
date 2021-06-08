#!/usr/bin/python3

import nmap
import os
import sys


print()
print("""
 ____                                  
/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ___) | (_| (_| | | | | | | |  __/ |   
|____/ \___\__,_|_| |_|_| |_|\___|_|""")
print()
print()

print()
print("[*] Herramienta para scanear vulnerabilidades en IPs")
print()
print("[*] Desarrollada por Shadow")
print()

host= input("Ingresa la IP objetivo: ")
nm= nmap.PortScanner()
results= nm.scan(hosts=host, arguments="-p- -v --open -sT -n -T5 -sV")
puertos_abiertos="-p "
count=0
#print (results)
print("Host : %s" % host)
print("State : %s" % nm[host].state())
for proto in nm[host].all_protocols():
    print('Protocol : %s' % proto)
    lport = nm[host][proto].keys()
    sorted(lport) 
    for port in lport:
        print ('Puerto : %s\tEstado : %s' % (port, nm[host][proto][port]['state']))
        if count==0:
            puertos_abiertos= puertos_abiertos+" "+str(port)
            count=1
        else:
            puertos_abiertos= puertos_abiertos+","+str(port)
print("Puertos abiertos: "+puertos_abiertos+" "+ str(host))  

 


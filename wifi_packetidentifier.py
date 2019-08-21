from scapy.all import *
class pidentifier(object):
	"""class"""
	def __init__(self,p):  
		self.p = p
		self.pktdic = {}  # 1x key or old is replaced
		
	def multi_paket_reader(self):
		localdict={}
		if self.p.haslayer(Dot11):
			try:
				sigstrength=-(256-ord(self.p.notdecoded[-4:-3]))
				localdict={"sigstren":sigstrength}
				self.pktdic.update(localdict)
			except:
				print 'error sigstrength'
			#  maybe name extra/not in a dict so the threadedsniffer has less to do :)
			if self.p[Dot11].type==0:  # managementtype
				localdict={"caster_mac":self.p[Dot11].addr2,"receiver_mac":self.p[Dot11].addr1}
				self.pktdic.update(localdict)
				if self.p[Dot11].subtype == 0:
					localdict={"name":"assoreq","caster":"cl","reqorres":"req"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 1:
					localdict={"name":"assores","caster":"ap","reqorres":"res"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 2:  # ESS didnt saw once
					localdict={"name":"reassoreq","caster":"cl","reqorres":"req"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 3:  # ESS didnt saw once
					localdict={"name":"reassores","caster":"ap","reqorres":"res"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 4:
					localdict={"name":"probereq","caster":"cl","reqorres":"req","searched_ssid":self.p.info}
					self.pktdic.update(localdict)
					#print'probreq from mac: '+self.pktdic.get("caster_mac")+' to find ssid: '+self.pktdic.get("searched_ssid")
				elif self.p[Dot11].subtype == 5:
					localdict={"name":"probres","caster":"ap","reqorres":"res","searched_ssid":self.p.info}
					self.pktdic.update(localdict)
					#print 'probres from mac: '+self.pktdic.get("caster_mac")+' to mac:'+self.pktdic.get("receiver_mac")
				elif self.p[Dot11].subtype == 8:  # BEACON-WORKS
					localdict={"name":"beacon","caster":"ap",
						"receiver_mac":"ff:ff:ff:ff:ff:ff","ssid":self.p.info}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 9:  # only in IBSS dint saw once
					localdict={"name":"ATIM","caster":"ap"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 10:  # hex?
					localdict={"name":"disasso","caster":"notsure"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 11:  # hex?
					localdict={"name":"auth","caster":"ithinkcl"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 12:  # hex?
					localdict={"name":"deauth","caster":"notsure"}
					self.pktdic.update(localdict)
				elif self.p[Dot11].subtype == 13:  # hex? didnt saw once
					localdict={"name":"action","caster":"ap"}
					self.pktdic.update(localdict)
				else:
					print 'unknown subtype in management'

			elif self.p[Dot11].type==1:  # controltype
				if self.p[Dot11].subtype == 13:  # hex?
					localdict={"name":"ack","caster":"clandap"}
					self.pktdic.update(localdict)
					"""test"""
					#print 'catched ack'
					"""testend"""
				else:
					pass#print 'unknown subtype in control'

			elif self.p[Dot11].type==2:  # datatype
				localdict={"caster":"clandap","caster_mac":self.p[Dot11].addr2,
					"receiver_mac":self.p[Dot11].addr1}
				self.pktdic.update(localdict)
				if self.p[Dot11].subtype == 0:
					self.pktdic["name"] = "data"
				elif self.p[Dot11].subtype == 4:
					self.pktdic["name"] = "null"
				elif self.p[Dot11].subtype == 8:  
					self.pktdic["name"] = "qosdata"
				elif self.p[Dot11].subtype == 12: # hex? 
					self.pktdic["name"] = "qosnull"
				else:
					print 'unknown subtype in data'
			else:
				print 'unknown Type'
		else:
			print 'no Dot11Layer'
	def check_beacon():
		pass
	"""classend - under construction"""
	
	
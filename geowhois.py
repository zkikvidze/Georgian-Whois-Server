#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket, os, re
from time import strftime
from netaddr import IPAddress, IPNetwork 
import urllib
import urllib2
import json
from bs4 import BeautifulSoup
import string


LISTEN_ADDRESS	=	"PUT_SERVER_ADDRESS_HERE"
LISTEN_PORT		=	4343
MAX_QUERY_SIZE	=	128
LOGFILE			=	"/var/log/geowhois.log"

n				=	"\r\n"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	s.bind((LISTEN_ADDRESS, LISTEN_PORT))
except:
	print("Could not bind specified IP or Port. Already in use? Not privileged for this port?")
	exit(2)
s.listen(1)



def sanitizeQuery(qr):
    qr = qr.lower()
    qr = qr.replace("..", ".")
    qr = qr.replace("/", "")
    qr = qr.replace("\\", "")
    qr = qr.replace(n, "")
    return qr



# Check if the input is a valid domain name
def isDomain(qr):
        regx = re.compile("^[a-z0-9\.-]+\.(ge|gov.ge|edu.ge|pvt.ge|com.ge|org.ge|net.ge)+\n")
        matches = regx.match(qr +"\n")
        if matches:
                #print 'regex passed'
                pass
        else:
                #print "verc veraferi"
                return False
        return True


def nicnetgequery(domain, tld):

        url = 'http://registration.ge/Home/DomainCheck'
        values = {'Domain': domain, 'TopLevelDomain' : tld}
        headers = {'Referer' : 'http://registration.ge/', 'X-Requested-With' : 'XMLHttpRequest'}

        data = urllib.urlencode(values)
        req = urllib2.Request(url, data, headers)
        try:
            response = urllib2.urlopen(req)
            page = response.read()

            json_data = json.loads(page)
            for x in json_data:
                response = json_data['Data']

            bs = BeautifulSoup(response, 'lxml')
            info = bs.find('div', {'class': 'info'})
            info = info.findAll(text=True)
            result =  unicode.join(u'\n', map(unicode, info))
            pass
        except:
	#	print "registration.ge unavailable"
	        return False
        #print result
	return result





def dnsgovquery(domain):

        url = 'https://dns.cloud.gov.ge/NsLookup.aspx'
        try:
            req1 = urllib2.urlopen(url).read()
            soup = BeautifulSoup(req1, 'lxml')
            viewstate = soup.select('#__VIEWSTATE')[0]['value']
            eventvalidation = soup.select('#__EVENTVALIDATION')[0]['value']


            values = {'__VIEWSTATE': viewstate, '__EVENTVALIDATION': eventvalidation, 'domain': domain, 'LookupButton': 'შემოწმება'}
            data = urllib.urlencode(values)
            req = urllib2.Request(url, data)
            response = urllib2.urlopen(req)
            page = response.read()

            bs = BeautifulSoup(page, 'lxml')
            zone = bs.find('span', {'id': 'lblZone'}).find(text=True)
            org = bs.find('span', {'id': 'lblOrganizationFullName'}).find(text=True)
            email = bs.find('span', {'id': 'lblEmail'}).find(text=True)
            tel = bs.find('span', {'id': 'lblTel'}).find(text=True)
            addr = bs.find('span', {'id': 'lblOrgAddress'}).find(text=True)
            info= 'Domain: ' + zone +'\n' + 'Organisation: ' + org + '\n' + 'Email: ' + email + '\n' + 'Phone: ' + tel + '\n' + 'Address: ' + email + '\n'
        except:
            #print "dns.cloud.gov.ge unavailable"
            return False
        return info



while True:
        try:
	    con, adr = s.accept()
        except:
            break
	log = "[" + strftime("%d/%m/%Y %H:%M:%S") + "] " + adr[0] + " - "
	while True:
                try:
		    query = con.recv(MAX_QUERY_SIZE)
                except:
                    break
#		print query
		if not query:
			break
		log = log + query.replace("\r\n", "").replace("\n", "") + " - "
		query = sanitizeQuery(query)	

		rsp = 		"# +-----------------------------------+" + n
		rsp = rsp + "# |      Security GE Whois Server     |" + n
		rsp = rsp + "# +-----------------------------------+" + n
		rsp = rsp + "# |  Works Only For .GE ccTLD Domains |" + n
		rsp = rsp + "# +-----------------------------------+" + n
		rsp = rsp + n

		if(isDomain(query)):
			# WHOIS Domain
			log = log + "Domain" + n
			#print query
                        name, tld = query.split('.',1)[-2:] 	
			if tld == 'gov.ge':
                            if(dnsgovquery(name)):
                                rsp = rsp + dnsgovquery(name)
                            else:
                                #print "trawi"
                                rsp = rsp + n
                                rsp = rsp + "Domain Not Registered" + n
                        else:
                            if(nicnetgequery(name, '.' + tld)):
                                rsp = rsp + nicnetgequery(name, '.' + tld)
                            else:
                                #print "trawi"
                                rsp = rsp + n
                                rsp = rsp + "Domain Not Registered" + n
			
		else:
			# Unrecognized	
			log = log + "Unrecognized" + n
			rsp = rsp + n
			rsp = rsp + "# Error. Unknown query type. Query is not .GE Domain " + n
		con.send(rsp.encode('utf-8'))
		con.close()
		if(LOGFILE!=""):
			# Save to logs
			try:
				d = open(LOGFILE, "a+")
				d.write(log)
				d.close()
			except:
				print("FAILED TO SAVE TO LOGFILE!")
		break

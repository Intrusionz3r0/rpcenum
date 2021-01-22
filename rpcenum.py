#!/usr/bin/env python3
import os
import pyfiglet,sys,signal
from prettytable import PrettyTable
from multiprocessing import Pool
from pwn import *


t1 = PrettyTable(['USERNAME',"RID" ,'DESCRIPTION'])
t2 = PrettyTable(['GROUPNAME',"RID", 'DESCRIPTION'])


def handler(key,frame):
	print(color['red']+"GoodBye!"+color['off'])
	sys.exit(1)

signal = signal.signal(signal.SIGINT,handler)


color = {
    'white':    "\033[1;37m",
    'yellow':   "\033[1;33m",
    'green':    "\033[1;32m",
    'blue':     "\033[1;34m",
    'cyan':     "\033[1;36m",
    'red':      "\033[1;31m",
    'magenta':  "\033[1;35m",
    'black':      "\033[1;30m",
    'darkwhite':  "\033[0;37m",
    'darkyellow': "\033[0;33m",
    'darkgreen':  "\033[0;32m",
    'darkblue':   "\033[0;34m",
    'darkcyan':   "\033[0;36m",
    'darkred':    "\033[0;31m",
    'darkmagenta':"\033[0;35m",
    'darkblack':  "\033[0;30m",
    'off':        "\033[0;0m"
}


def getRIDU(IP):
	rusers = os.popen('rpcclient {} -U "" -N -c "enumdomusers" | cut -d "[" -f 3 | cut -d "]" -f 1'.format(IP)).read().split('\n')
	r=[]

	for x in range(len(rusers)):
		if (rusers[x] != ""):
			r.append(IP+":"+rusers[x])

	return r

def getRIDG(IP):
	rgroups = os.popen('rpcclient {} -U "" -N -c "enumdomgroups" | cut -d "[" -f3 | cut -d "]" -f1'.format(IP)).read().split('\n')
	r=[]

	for x in range(len(rgroups)):
		if(rgroups[x] != ""):
			r.append(IP+":"+rgroups[x])

	return r


def getUser(params):
	ip = params.split(":")[0]
	rid = params.split(":")[1]

	user = os.popen('rpcclient {} -U "" -N -c "queryuser {}" | grep "User Name" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	user = user.strip()

	desc = os.popen('rpcclient {} -U "" -N -c "queryuser {}" | grep "Description" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	desc = desc.strip()

	user = user+":"+desc+":"+rid
	return user


def getGroups(params):
	ip = params.split(":")[0]
	rid = params.split(":")[1]

	group = os.popen('rpcclient {} -U "" -N -c "querygroup {}" | grep "Group Name" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	group = group.strip()

	desc = os.popen('rpcclient {} -U "" -N -c "querygroup {}" | grep "Description" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	desc= desc.strip()

	gg = group+":"+desc+":"+rid
	return gg


def writeUserFile(user):
	file = open("users.txt","a")
	file.write(user+"\n")
	file.close()

def nullSession(IP):

	p1 = log.progress("Users")

	print(color['darkcyan'])
	p1.status("Collecting information from users.")
	print(color['off'])

	pool = Pool(processes=50)
	data = getRIDU(IP)
	u=[]
	for user in pool.imap_unordered(getUser,[line for line in data]):
		u.append(user)
		user = user.split(":")[0]
		writeUserFile(user)

	printTableU(u)

	print(color['darkcyan'])
	p1.success("finalized.")
	print(color['off'])

	p2 = log.progress("Groups")
	print(color['darkcyan'])
	p2.status("Collecting information from groups.")
	print(color['off'])
	data2= getRIDG(IP)
	g=[]

	for group in pool.imap_unordered(getGroups,[line for line in data2]):
		g.append(group)

	printTableG(g)

	print(color['darkcyan'])
	p2.success("finalized.")
	print(color['off'])


def printTableU(data):
	for x in data:
		user= x.split(":")[0]
		desc=x.split(":")[1]
		rid=x.split(":")[2]
		t1.add_row([user,rid,desc])

	print(color['darkwhite'])
	print(t1)
	print(color['off'])

def printTableG(data):
	for x in data:
		group= x.split(":")[0]
		desc= x.split(":")[1]
		rid=x.split(":")[2]
		t2.add_row([group,rid,desc])

	print(color['darkwhite'])
	print(t2)
	print(color['off'])


def banner():
	print(color['red'])
	print(pyfiglet.figlet_format("RPCENUM"))
	print(color['off'])
	print(color['darkblack'] +" "*20+ "By Intrusionz3r0 (v1.0)"+ color['off'])

if __name__ == "__main__":
	banner()
	IP = sys.argv[1]
	print("\n")
	nullSession(IP)

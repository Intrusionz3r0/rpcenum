#!/usr/bin/env python3
#Author: Intrusionz3r0
import os
import pyfiglet,sys,signal,argparse
from prettytable import PrettyTable
from multiprocessing import Pool
from pwn import *


t1 = PrettyTable(['RID',"USERNAME" ,'NAME',"DESCRIPTION"])
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



def banner():
	print(color['red'])
	print(pyfiglet.figlet_format("RPCENUM"))
	print(color['off'])
	print(color['yellow'] +" "*20+ "By Intrusionz3r0 (v2.0)"+ color['off'])



def getRIDG(IP):
	rgroups = os.popen('rpcclient {} -U "" -N -c "enumdomgroups" | cut -d "[" -f3 | cut -d "]" -f1'.format(IP)).read().split('\n')
	r=[]

	for x in range(len(rgroups)):
		if(rgroups[x] != ""):
			r.append(IP+"[$]"+rgroups[x])

	return r

def getRIDGCredentials(IP,USERNAME,PASSWORD):
	rgroups = os.popen('rpcclient {} -U "{}%{}" -c "enumdomgroups" | cut -d "[" -f3 | cut -d "]" -f1'.format(IP,USERNAME,PASSWORD)).read().split('\n')
	r=[]

	for x in range(len(rgroups)):
		if(rgroups[x] != ""):
			r.append(IP+"[$]"+USERNAME+"[$]"+PASSWORD+"[$]"+rgroups[x])

	return r

def getGroupCredentials(params):
	ip = params.split("[$]")[0]
	user = params.split("[$]")[1]
	password = params.split("[$]")[2]
	rid = params.split("[$]")[3]

	group = os.popen('rpcclient {} -U "{}%{}" -c "querygroup {}" | grep "Group Name" | cut -d ":" -f2 | xargs'.format(ip,user,password,rid)).read()
	group = group.strip()

	desc = os.popen('rpcclient {} -U "{}%{}" -c "querygroup {}" | grep "Description" | cut -d ":" -f2 | xargs'.format(ip,user,password,rid)).read()
	desc= desc.strip()

	gg = group+"[$]"+desc+"[$]"+rid
	return gg


def getGroup(params):
	ip = params.split("[$]")[0]
	rid = params.split("[$]")[1]

	group = os.popen('rpcclient {} -U "" -N -c "querygroup {}" | grep "Group Name" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	group = group.strip()

	desc = os.popen('rpcclient {} -U "" -N -c "querygroup {}" | grep "Description" | cut -d ":" -f2 | xargs'.format(ip,rid)).read()
	desc= desc.strip()

	gg = group+"[$]"+desc+"[$]"+rid
	return gg


def nullsession(IP):
	p1 = log.progress("Users")
	p1.status("Collecting information from users.")

	request = os.popen('rpcclient {} -U "" -N -c "querydispinfo2" > data.tmp'.format(IP)).read().split('\n')

	users = os.popen("cat data.tmp | awk '{print $8}'").read().split("\n")
	rids = os.popen("cat data.tmp | awk '{print $4}'").read().split("\n")
	names= os.popen("cat data.tmp | awk '{print $1}' FS='Desc:' | awk '{print $2}' FS='Name: ' | sed 's/^[ \t]*//;s/[ \t]*$//'").read().split("\n")
	desc = os.popen("cat data.tmp | cut -d':' -f7 | sed 's/^[ \t]*//;s/[ \t]*$//'").read().split("\n")

	p1.status("Export users file.")
	time.sleep(1)
	writeUsersFile(users)
	printTableUsers(rids,users,names,desc)

	p1.success("finalized.")
	pool = Pool(processes=50)
	p2 = log.progress("Groups")
	p2.status("Collecting information from groups.")
	groupsinfo = getRIDG(IP)
	g=[]
	for group in pool.imap_unordered(getGroup,[line for line in groupsinfo]):
		g.append(group)

	printTableG(g)
	p2.success("finalized.")


def rpcenumcredentials(IP,USERNAME,PASSWORD):
	p1 = log.progress("Users")
	p1.status("Collecting information from users.")

	request = os.popen('rpcclient {} -U "{}%{}" -c "querydispinfo2" > data.tmp'.format(IP,USERNAME,PASSWORD)).read().split('\n')

	users = os.popen("cat data.tmp | awk '{print $8}'").read().split("\n")
	rids = os.popen("cat data.tmp | awk '{print $4}'").read().split("\n")
	names= os.popen("cat data.tmp | awk '{print $1}' FS='Desc:' | awk '{print $2}' FS='Name: ' | sed 's/^[ \t]*//;s/[ \t]*$//'").read().split("\n")
	desc = os.popen("cat data.tmp | cut -d':' -f7 | sed 's/^[ \t]*//;s/[ \t]*$//'").read().split("\n")

	p1.status("Export users file.")
	time.sleep(1)
	writeUsersFile(users)
	printTableUsers(rids,users,names,desc)
	p1.success("finalized.")
	pool = Pool(processes=50)
	p2 = log.progress("Groups")
	p2.status("Collecting information from groups.")
	groupsinfo = getRIDGCredentials(IP,USERNAME,PASSWORD)
	g=[]
	for group in pool.imap_unordered(getGroupCredentials,[line for line in groupsinfo]):
		g.append(group)

	printTableG(g)
	p2.success("finalized.")

def printTableUsers(rids,users,names,desc):
	for x in range(len(rids)):
		if(rids[x] != ""):
			t1.add_row([rids[x],users[x],names[x],desc[x]])
	print(color['darkwhite'])
	print(t1)
	print(color['off'])
	os.remove("data.tmp")


def printTableG(data):
	for x in data:
		group= x.split("[$]")[0]
		desc= x.split("[$]")[1]
		rid=x.split("[$]")[2]
		t2.add_row([group,rid,desc])

	print(color['darkwhite'])
	print(t2)
	print(color['off'])


def writeUsersFile(users):
	file = open("users.txt","w+")
	for x in users:
		if(x != ""):
			file.write(x+"\n")
	file.close()



if __name__ == "__main__":
	banner()

	print(color['darkwhite'])
	parser = argparse.ArgumentParser()
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='how to use.')
	parser = argparse.ArgumentParser(prog='python3', usage='%(prog)s rpcenum.py [options]')
	parser.add_argument("-I", "--ipaddress" , help="specify destination IP address.")
	parser.add_argument("-U", "--username" , help="set username.")
	parser.add_argument("-P", "--password" , help="set password.")
	args = parser.parse_args()
	color['off']

	if(args.ipaddress and args.username or args.password):
		print("\n")
		rpcenumcredentials(args.ipaddress,args.username,args.password)
		sys.exit(0)

	elif(args.ipaddress):
		print("\n")
		nullsession(args.ipaddress)
		sys.exit(0)


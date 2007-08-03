#!/usr/bin/env python

"""
Based on ljdump; original ljdump license & header at the bottom of this file.
Extensive modifications by antennapedia@livejournal.
Version 1.3
3 August 2007

- uses Configparser instead of xml for config, since we are not insane
- dumps to a directory structure like this:
  username/
  	entry000001
  		entry.xml
  		comments.xml
  	entry000002
  		entry.xml
  		comments.xml
  	userpics
  		keyword1.jpeg
  		keyword2.png
  	metadata/
  		(cache info, including the last time we synced)
	
"""

import codecs
import exceptions
import imghdr
import md5
import os
import pickle
import pprint
import re
import sys
import time
import urllib2
import xml.dom.minidom
import xmlrpclib
from xml.sax import saxutils
import ConfigParser

configpath = "ljmigrate.cfg"

global gSourceAccount, gDestinationAccount

# more config, which shouldn't need to change

# lj's time format
# 2004-08-11 13:38:00
ljTimeFormat = '%Y-%m-%d %H:%M:%S'

def parsetime(input):
	try:
		return time.strptime(input, ljTimeFormat)
	except ValueError, e:
		#print e
		return ()

class Entry(object):
	def __init__(self, dict):
		for k in dict.keys():
			self.__dict__[k] = dict[k]
		pprint.pprint(self)

class Account(object):

	def __init__(self, host="", user="", password=""):
		m = re.search("(.*)/interface/xmlrpc", host)
		if m:
			self.host = m.group(1)
		else:
			self.host = host
		
		self.user = user
		self.password = password
		self.flat_api = self.host + "/interface/flat"
		self.server_proxy = xmlrpclib.ServerProxy(self.host+"/interface/xmlrpc")
		self.session = ""
		
		self.metapath = os.path.join(user, "metadata")
		
	def openMetadataFile(self, name):
		""" Convenience. """
		if not os.path.exists(self.metapath):
			os.makedirs(self.metapath)
		fp = open(os.path.join(self.metapath, name), 'w')
		return fp
	
	def readMetaDataFile(self, name):
		fp = open(os.path.join(self.metapath, name), 'r')
		return fp

	def makeSession(self):
		r = urllib2.urlopen(self.flat_api, "mode=getchallenge")
		response = self.handleFlatResponse(r)
		r.close()
		r = urllib2.urlopen(self.flat_api, "mode=sessiongenerate&user=%s&auth_method=challenge&auth_challenge=%s&auth_response=%s" % 
				(self.user, response['challenge'], self.calcChallenge(response['challenge']) ))
		response = self.handleFlatResponse(r)
		r.close()
		self.session = response['ljsession']
		
	def handleFlatResponse(self, response):
		r = {}
		while True:
			name = response.readline()
			if len(name) == 0:
				break
			if name[-1] == '\n':
				name = name[:len(name)-1]
			value = response.readline()
			if value[-1] == '\n':
				value = value[:len(value)-1]
			r[name] = value
		return r
	
	def doChallenge(self, params):
		challenge = self.server_proxy.LJ.XMLRPC.getchallenge()
		params.update({
			'auth_method': "challenge",
			'auth_challenge': challenge['challenge'],
			'auth_response': self.calcChallenge(challenge['challenge'])
		})
		return params

	def calcChallenge(self, challenge):
		return md5.new(challenge+md5.new(self.password).hexdigest()).hexdigest()
		
	def getUserPics(self):
		resp = gSourceAccount.server_proxy.LJ.XMLRPC.login(self.doChallenge({
			'username': self.user,
			'ver': 1,
			'getpickws': 1,
			'getpickwurls': 1,
		}))
		return resp
	
	def getSyncItems(self, lastsync):
		r = gSourceAccount.server_proxy.LJ.XMLRPC.syncitems(self.doChallenge({
			'username': self.user,
			'ver': 1,
			'lastsync': lastsync,
		} ))
		#pprint.pprint(r)
		return r['syncitems']
		
	def getOneEvent(self, itemid):
		e = self.server_proxy.LJ.XMLRPC.getevents(self.doChallenge({
			'username': self.user,
			'ver': 1,
			'selecttype': "one",
			'itemid': itemid,
		}))
		return e['events'][0]
		
	def postEntry(self, entry):
		#pprint.pprint(entry)
		params = {
			'username': self.user,
			'ver': 1,
			'lineendings': 'unix',
		}
		if entry.has_key('subject'): params['subject'] = entry['subject']
		if entry.has_key('event'): params['event'] = entry['event']
		if entry.has_key('security'): params['security'] = entry['security']
		if entry.has_key('allowmask'): params['allowmask'] = entry['allowmask']
		if entry.has_key('props'): params['props'] = entry['props']
		
		timetuple = parsetime(entry['eventtime'])
		if len(timetuple) < 5:
			return 0

		params['year'] = timetuple[0]
		params['mon'] = timetuple[1]
		params['day'] = timetuple[2]
		params['hour'] = timetuple[3]
		params['min'] = timetuple[4]

		params = self.doChallenge(params)
		result = self.server_proxy.LJ.XMLRPC.postevent(params)
		return result

###

def dumpelement(f, name, e):
	f.write("<%s>\n" % name)
	for k in e.keys():
		if isinstance(e[k], {}.__class__):
			dumpelement(f, k, e[k])
		else:
			s = unicode(str(e[k]), "UTF-8")
			f.write("<%s>%s</%s>\n" % (k, saxutils.escape(s), k))
	f.write("</%s>\n" % name)


def makeItemName(id, type):
	if id.startswith('L-') or id.startswith('C-'):
		idstr = "%05d" % (int(id[2:]), )
	else:
		idstr = "%05d" % (int(id), )
	if type == 'entry':
		return "%s%s" % (type, idstr)
	return idstr

def writedump(user, itemid, type, event):
	itemname = makeItemName(itemid, type)
	path = os.path.join(user, itemname)
	if not os.path.exists(path):
		os.makedirs(path)
	fn = os.path.join(path, "%s.xml" % (type, ))
	f = codecs.open(fn, "w", "UTF-8")
	f.write("""<?xml version="1.0"?>\n""")
	dumpelement(f, "event", event)
	f.close()

def createxml(doc, name, map):
	e = doc.createElement(name)
	for k in map.keys():
		me = doc.createElement(k)
		me.appendChild(doc.createTextNode(map[k]))
		e.appendChild(me)
	return e

def gettext(e):
	if len(e) == 0:
		return ""
	return e[0].firstChild.nodeValue
	
def canonicalizeFilename(input):
	result = input.replace(os.sep, "|")
	result = result.replace(' ', '_')
	return result


def fetchConfig():
	global gSourceAccount, gDestinationAccount
	cfparser = ConfigParser.ConfigParser()
	try:
		cfparser.readfp(open(configpath))
	except StandardError, e:
		error("Problem reading config file: %s" % str(e))
	
	gSourceAccount = Account(cfparser.get('source', 'server'), cfparser.get('source', 'user'), cfparser.get('source', 'password'))
	gDestinationAccount = Account(cfparser.get('destination', 'server'), cfparser.get('destination', 'user'), cfparser.get('destination', 'password'))

	
def main():
	fetchConfig()

	print "Fetching journal entries for: %s" % gSourceAccount.user
	if not os.path.exists(gSourceAccount.user):
		os.makedirs(gSourceAccount.user)
		print "Created subdirectory: %s" % gSourceAccount.user
	
	gSourceAccount.makeSession()
	
	newentries = 0
	newcomments = 0
	commentsBy = 0
	errors = 0
	
	lastsync = ""
	lastmaxid = 0
	try:
		f = gSourceAccount.readMetaDataFile("last_sync")
		lastsync = f.readline()
		if lastsync[-1] == '\n':
			lastsync = lastsync[:len(lastsync)-1]
		lastmaxid = f.readline()
		if len(lastmaxid) > 0 and lastmaxid[-1] == '\n':
			lastmaxid = lastmaxid[:len(lastmaxid)-1]
		if lastmaxid == "":
			lastmaxid = 0
		else:
			lastmaxid = int(lastmaxid)
		f.close()
	except:
		pass
	origlastsync = lastsync
	
	r = gSourceAccount.getUserPics()
	userpics = dict(zip(r['pickws'], r['pickwurls']))
	
	while True:
		syncitems = gSourceAccount.getSyncItems(lastsync)
		if len(syncitems) == 0:
			break
		for item in syncitems:
			if item['item'][0] == 'L':
				print "Fetching journal entry %s (%s)" % (item['item'], item['action'])
				try:
					entry = gSourceAccount.getOneEvent(item['item'][2:])
					writedump(gSourceAccount.user, item['item'], 'entry', entry)
					print "    posting journal entry to destination account..."
					result = gDestinationAccount.postEntry(entry)
					newentries += 1
				except exceptions.Exception, x:
					print "Error getting item: %s" % item['item']
					pprint.pprint(x)
					errors += 1
			elif item['item'].startswith('C-'):
				commentsBy += 1
				#print "Skipping comment %s by user (%s)" % (item['item'], item['action'])
			else:
				pprint.pprint(item)
			lastsync = item['time']
	
	print "Fetching journal comments for: %s" % gSourceAccount.user
	
	try:
		f = gSourceAccount.readMetaDataFile('comment.meta')
		metacache = pickle.load(f)
		f.close()
	except:
		metacache = {}
	
	try:
		f = gSourceAccount.readMetaDataFile('user.map')
		usermap = pickle.load(f)
		f.close()
	except:
		usermap = {}
	
	maxid = lastmaxid
	while True:
		r = urllib2.urlopen(urllib2.Request(gSourceAccount.host+"/export_comments.bml?get=comment_meta&startid=%d" % (maxid+1), headers = {'Cookie': "ljsession="+gSourceAccount.session}))
		meta = xml.dom.minidom.parse(r)
		r.close()
		for c in meta.getElementsByTagName("comment"):
			id = int(c.getAttribute("id"))
			metacache[id] = {
				'posterid': c.getAttribute("posterid"),
				'state': c.getAttribute("state"),
			}
			if id > maxid:
				maxid = id
		for u in meta.getElementsByTagName("usermap"):
			usermap[u.getAttribute("id")] = u.getAttribute("user")
		if maxid >= int(meta.getElementsByTagName("maxid")[0].firstChild.nodeValue):
			break
	
	f = gSourceAccount.openMetadataFile('comment.meta')
	pickle.dump(metacache, f)
	f.close()
	
	f = gSourceAccount.openMetadataFile('user.map')
	pickle.dump(usermap, f)
	f.close()
	
	print "Fetching userpics for: %s" % gSourceAccount.user
	path = os.path.join(gSourceAccount.user, "userpics")
	if not os.path.exists(path):
		os.makedirs(path)
	f = gSourceAccount.openMetadataFile("userpics.xml")
	print >>f, """<?xml version="1.0"?>"""
	print >>f, "<userpics>"
	for p in userpics:
		print >>f, """<userpic keyword="%s" url="%s" />""" % (p, userpics[p])
		r = urllib2.urlopen(userpics[p])
		if r:
			data = r.read()
			type = imghdr.what(r, data)
			if p == "*":
				picfn = os.path.join(path, "default.%s" % type)
			else:
				picfn = os.path.join(path, "%s.%s" % (canonicalizeFilename(p), type))
			picfp = open(picfn, 'w')
			picfp.write(data)
			picfp.close()
	print >>f, "</userpics>"
	f.close()
	
	newmaxid = maxid
	maxid = lastmaxid
	while True:
		r = urllib2.urlopen(urllib2.Request(gSourceAccount.host+"/export_comments.bml?get=comment_body&startid=%d" % (maxid+1), headers = {'Cookie': "ljsession="+gSourceAccount.session}))
		meta = xml.dom.minidom.parse(r)
		r.close()
		for c in meta.getElementsByTagName("comment"):
			id = int(c.getAttribute("id"))
			jitemid = c.getAttribute("jitemid")
			comment = {
				'id': str(id),
				'parentid': c.getAttribute("parentid"),
				'subject': gettext(c.getElementsByTagName("subject")),
				'date': gettext(c.getElementsByTagName("date")),
				'body': gettext(c.getElementsByTagName("body")),
				'state': metacache[id]['state'],
			}
			if usermap.has_key(c.getAttribute("posterid")):
				comment["user"] = usermap[c.getAttribute("posterid")]
			try:
				entry = xml.dom.minidom.parse("%s/C-%s" % (gSourceAccount.user, jitemid))
			except:
				entry = xml.dom.minidom.getDOMImplementation().createDocument(None, "comments", None)
			found = False
			for d in entry.getElementsByTagName("comment"):
				if int(d.getElementsByTagName("id")[0].firstChild.nodeValue) == id:
					found = True
					break
			if found:
				print "Warning: downloaded duplicate comment id %d in jitemid %s" % (id, jitemid)
			else:
				entry.documentElement.appendChild(createxml(entry, "comment", comment))				
				path = os.path.join(gSourceAccount.user, makeItemName(jitemid, 'entry'))
				if not os.path.exists(path):
					os.makedirs(path)
				f = codecs.open(os.path.join(path, "comments.xml"), "w", "UTF-8")
				entry.writexml(f)
				f.close()
				newcomments += 1
			if id > maxid:
				maxid = id
		if maxid >= newmaxid:
			break
	
	lastmaxid = maxid
	
	f = gSourceAccount.openMetadataFile('last_sync')
	f.write("%s\n" % lastsync)
	f.write("%s\n" % lastmaxid)
	f.close()
	
	if origlastsync:
		print "%d new entries, %d new comments (since %s),  %d new comments by user, %d userpics" % (newentries, newcomments, origlastsync, commentsBy, len(userpics))
	else:
		print "%d entries, %d comments, %d comments by user, %d userpics" % (newentries, newcomments, commentsBy, len(userpics))
	if errors > 0:
		print "%d errors" % errors
	
if __name__ == '__main__':
	main()

# ljdump.py - livejournal archiver
# Greg Hewgill <greg@hewgill.com> http://hewgill.com
# Version 1.2
# $Id: ljdump.py 17 2006-09-08 08:46:56Z greg $
#
# This program reads the journal entries from a livejournal (or compatible)
# blog site and archives them in a subdirectory named after the journal name.
#
# The configuration is read from "ljdump.config". A sample configuration is
# provided in "ljdump.config.sample", which should be copied and then edited.
# The configuration settings are:
#
#   server - The XMLRPC server URL. This should only need to be changed
#			if you are dumping a journal that is livejournal-compatible
#			but is not livejournal itself.
#
#   username - The livejournal user name. A subdirectory will be created
#			  with this same name to store the journal entries.
#
#   password - The account password. This password is never sent in the
#			  clear; the livejournal "challenge" password mechanism is used.
#
# This program may be run as often as needed to bring the backup copy up
# to date. Both new and updated items are downloaded.
#
# LICENSE
#
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#	claim that you wrote the original software. If you use this software
#	in a product, an acknowledgment in the product documentation would be
#	appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#	misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2005-2006 Greg Hewgill

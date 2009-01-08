#!/usr/bin/env python

"""
Based on ljdump; original ljdump license & header in LICENCE.text.
Extensive modifications by antennapedia.
Version 1.5
7 January 2009

BSD licence mumbo-jumbo to follow. By which I mean, do what you want.
See README.text for documentation.
"""

import codecs
import exceptions
import fnmatch
import httplib
import imghdr
import math
import md5
from optparse import OptionParser
import os
import pickle
import pprint
import re
import socket
import sys
import time
import traceback
import types
import urllib2
import xml.dom.minidom
import xmlrpclib
from xml.sax import saxutils
import ConfigParser

__version__ = '1.5 090107c Wed Jan  7 17:20:49 PST 2009'
__author__ = 'Antennapedia'
__license__ = 'BSD license'

configpath = "ljmigrate.cfg"

# hackity hack
global gSourceAccount, gDestinationAccount, gAllEntries, gMigrate, gGenerateHtml, gMigrationTags

# lj's time format: 2004-08-11 13:38:00
ljTimeFormat = '%Y-%m-%d %H:%M:%S'

def parsetime(input):
	try:
		return time.strptime(input, ljTimeFormat)
	except ValueError, e:
		#print e
		return ()
		

# Stolen directly from the python xmlrpclib documentation.
class ProxiedTransport(xmlrpclib.Transport):

	def setProxy(self, proxy):
		self.proxyhost = proxy

	# overridden
	def make_connection(self, host):
		self.realhost = host
		h = httplib.HTTP(self.proxyhost)
		return h

	# overridden
	def send_request(self, connection, handler, request_body):
		connection.putrequest("POST", 'http://%s%s' % (self.realhost, handler))
		
	# overridden
	def send_host(self, connection, host):
		connection.putheader('Host', self.realhost)


class Account(object):

	def __init__(self, host="", user="", password="", proxyHost=None, proxyPort=None):
		if host.endswith('/'):
			host = host[:-1]
		m = re.search("(.*)/interface/xmlrpc", host)
		if m:
			self.host = m.group(1)
		else:
			self.host = host
		
		m = re.search("http://(.*)", host)
		if m:
			self.site = m.group(1)
		else:
			self.site = host
			self.host = "http://" + host
		
		self.user = user
		self.password = password
		self.flat_api = self.host + "/interface/flat"
		
		if proxyHost != None:
			proxy = proxyHost
			if proxyPort != None:
				proxy = proxy + ":" + proxyPort
			transportProxy = ProxiedTransport()
			transportProxy.setProxy(proxy)
			# Note overloaded term "proxy". The xmlrpclib does this, unfortunately.
			self.server_proxy = xmlrpclib.ServerProxy(self.host+"/interface/xmlrpc", transport=transportProxy)
		else:
			# default transport
			self.server_proxy = xmlrpclib.ServerProxy(self.host+"/interface/xmlrpc")

		self.session = ""
		self.journal = user
		self.journal_list = []
		self.groupmap = None
		self.readUserPicInfo()
	
	def metapath(self):
		return os.path.join(self.journal, "metadata")
		
	def openMetadataFile(self, name, usecodec = 1):
		""" Convenience. """
		if not os.path.exists(self.metapath()):
			os.makedirs(self.metapath())
		if usecodec:
			fp = codecs.open(os.path.join(self.metapath(), name), 'w', 'utf-8', 'replace')
		else:
			fp = open(os.path.join(self.metapath(), name), 'w')
		return fp
	
	def readMetadataFile(self, name, usecodec = 1):
		if usecodec:
			fp = codecs.open(os.path.join(self.metapath(), name), 'r', 'utf-8', 'replace')
		else:
			fp = open(os.path.join(self.metapath(), name), 'r')
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
		while 1:
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
		params = {
			'username': self.user,
			'ver': 1,
			'getpickws': 1,
			'getpickwurls': 1,
		}
		if self.journal != self.user:
			params['usejournal'] = self.journal
		params = self.doChallenge(params)
		resp = self.server_proxy.LJ.XMLRPC.login(params)
		return resp
	
	def getSyncItems(self, lastsync):
		params = {
			'username': self.user,
			'ver': 1,
			'lastsync': lastsync,
		}
		if self.journal != self.user:
			params['usejournal'] = self.journal

		params = self.doChallenge(params)
		r = self.server_proxy.LJ.XMLRPC.syncitems(params)
		return r['syncitems']
		
	def getOneEvent(self, itemid):
		params = {
			'username': self.user,
			'ver': 1,
			'selecttype': "one",
			'itemid': itemid,
		}
		if self.journal != self.user:
			params['usejournal'] = self.journal
		
		params = self.doChallenge(params)
		e = self.server_proxy.LJ.XMLRPC.getevents(params)
		if len(e['events']) > 0:
			return e['events'][0]
		else:
			ljmLog(e)
			return None
		
	def postEntry(self, entry):
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
		if entry.has_key('props'): 
			params['props'] = entry['props']
		else:
			params['props'] = {}

		if self.journal != self.user:
			params['usejournal'] = self.journal
		else:
			# LJ does not allow you to create backdated entries in communities
			params['props']['opt_backdated'] = 1
		
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

	def editEntry(self, entry, destid):
		params = {
			'username': self.user,
			'ver': 1,
			'lineendings': 'unix',
			'itemid': destid,
		}

		if self.journal != self.user:
			params['usejournal'] = self.journal
		
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
		result = self.server_proxy.LJ.XMLRPC.editevent(params)
		return result

	def deleteEntry(self, entryid):
		params = {
			'username': self.user,
			'ver': 1,
			'lineendings': 'unix',
			'itemid': entryid,
			'event': '',
			# all other fields empty
		}
		if self.journal != self.user:
			params['usejournal'] = self.journal
		
		params = self.doChallenge(params)
		result = self.server_proxy.LJ.XMLRPC.editevent(params)
		return result
	
	def getfriendgroups(self):
		params = {
			'username': self.user,
			'ver': 1,
			'lineendings': 'unix',
		}
		
		params = self.doChallenge(params)
		result = self.server_proxy.LJ.XMLRPC.getfriendgroups(params)
		return result
		
	def getfriends(self):
		params = {
			'username': self.user,
			'ver': 1,
			'lineendings': 'unix',
		}
		
		params = self.doChallenge(params)
		result = self.server_proxy.LJ.XMLRPC.getfriends(params)
		return result
	
	def readUserPicInfo(self):
		self.userpictypes = {}
		self.userPictHash = {}
		try:
			path = os.path.join(self.user, "userpics")
			fp = self.readMetadataFile("userpics.xml")
			string = fp.read()
			fp.close()
			string = string.encode("utf-8", "replace")
			iconXML = xml.dom.minidom.parseString(string)
			for p in iconXML.getElementsByTagName("userpic"):
				key = p.getAttribute('keyword')
				type = p.getAttribute('type')
				self.userpictypes[key] = type
				picfn = os.path.join(path, "%s.%s" % (canonicalizeFilename(key), type))
				self.userPictHash[key] = picfn
		except Exception, e:
			# eat the error and just get them all fresh
			# print e
			pass
	
		
	def fetchUserPics(self, dontFetchImageData=1):
		ljmLog("Recording userpic keyword info for: %s" % self.user)
	
		r = self.getUserPics()
		userpics = {}
		for i in range(0, len(r['pickws'])):
			userpics[str(r['pickws'][i])] = r['pickwurls'][i]
		userpics['default'] = r['defaultpicurl']

		path = os.path.join(self.user, "userpics")
		if not os.path.exists(path):
			os.makedirs(path)
		f = self.openMetadataFile("userpics.xml")
		
		f.write('<?xml version="1.0" encoding="utf-8" ?>\n')
		f.write("<userpics>\n")
		for p in userpics:
			kwd = p.decode('utf-8', 'replace')
			
			doDownload = 0
			if self.userpictypes.has_key(kwd):
				picfn = os.path.join(path, "%s.%s" % (canonicalizeFilename(kwd), self.userpictypes[kwd]))
				if not os.path.exists(picfn):
					doDownload = 1
			else:
				doDownload = 1
			if dontFetchImageData: doDownload = 0 # but respect the flag
			
			if doDownload:
				ljmLog(u'    Getting image data for keywords "%s"' % kwd.encode('ascii', 'replace'))
				try:
					r = urllib2.urlopen(userpics[p])
					if r:
						data = r.read()
						type = imghdr.what(r, data)
						self.userpictypes[p] = type
						if p == "*":
							picfn = os.path.join(path, "default.%s" % type)
						else:
							picfn = os.path.join(path, "%s.%s" % (canonicalizeFilename(p), type))
						self.userPictHash[kwd] = unicode(picfn, 'utf-8', 'replace')
						picfp = open(picfn, 'w')
						picfp.write(data)
						picfp.close()
				except:
					pass
			f.write(u'<userpic keyword="%s" url="%s" type="%s" />\n' % (saxutils.escape(kwd), userpics[p], self.userpictypes.get(p, "")))

		f.write("</userpics>\n")
		f.close()
		
	def readGroupMap(self):
		if self.groupmap == None:
			try:
				f = self.readMetadataFile('friendgroups.meta')
				groupmap = pickle.load(f)
				f.close()
			except:
				# just start fresh
				groupmap = {}
			self.groupmap = groupmap
			
	def readAllEntryFiles(self):
		from StringIO import StringIO
		result = {}
		inputdir = self.journal

		for root, dirs, files in os.walk(inputdir):
			if '.svn' in dirs: dirs.remove('.svn')	
			if '.svn' in dirs: dirs.remove('html')	
			if '.svn' in dirs: dirs.remove('metadata')	
			if '.svn' in dirs: dirs.remove('userpics')	
			yfiles = fnmatch.filter(files, 'entry.xml')
		
			for fname in yfiles:
				path = os.path.join(root, fname)
				entryxml = xml.dom.minidom.parse(path)
				for e in entryxml.getElementsByTagName("event"):
					test = e.getElementsByTagName('itemid')
					if len(test) == 0: continue
					entrydict = nodeToDict(e)
					eobj = Entry(entrydict, self.user, self.journal)
					result[entrydict['itemid']] = eobj
		return result

###

def nodeToDict(node):
	result = {}
	for child in node.childNodes:
		if child.nodeType == node.TEXT_NODE:
			continue
		result[child.tagName] = nodeToDict(child)	
	if len(result.keys()) == 0:
		return getTextFromNode(node.childNodes)
	return result
	
def getTextFromNode(nodelist):
	rc = ""
	for node in nodelist:
		if node.nodeType == node.TEXT_NODE:
			rc = rc + node.data
	return rc

### inherited functions from ljdump; TODO re-examine

def dumpelement(f, name, e):
	f.write("<%s>\n" % name)
	for k in e.keys():
		if isinstance(e[k], {}.__class__):
			dumpelement(f, k, e[k])
		else:
			s = unicode(str(e[k]), "UTF-8", 'replace')
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

#-------------------------------------------------------------------------------
# logging utilities

def ljmLog(message):
	try:
		print message
	except:
		print "error logging message, of all things"
	try:
		gSourceAccount.runlog.write(message+"\n")
	except:
		pass

def ljmException(message, exc):
	try:
		print "ERROR:", message, str(exc)
		traceback.print_exc(5)
	except:
		print "error printing error message, of all things"
	try:
		gSourceAccount.runlog.write(message+"\n")
		text = traceback.format_exc(5)
		gSourceAccount.runlog.write(text+"\n")
	except:
		pass
		
def endLogging():
	ljmLog("Run ended normally: %s" % time.asctime())
	gSourceAccount.runlog.close()


#-------------------------------------------------------------------------------
# configuration file parsing

def fetchConfig():
	# needs major refactoring. sigh.
	global gSourceAccount, gDestinationAccount, gMigrate, gGenerateHtml, gMigrateOwnOnly, gMigrationTags
	try:
		cfparser = ConfigParser.SafeConfigParser()
	except StandardError, e:
		cfparser = ConfigParser.ConfigParser()
		
	try:
		cfparser.readfp(open(options.configFile))
	except StandardError, e:
		print "Problem reading config file: %s" % str(e)
		sys.exit()
	
	pHost = None
	pPort = None
	try:
		pHost = cfparser.get('proxy', 'host')
		pPort = cfparser.get('proxy', 'port')
	except ConfigParser.NoSectionError, e:
		# not an error, because the proxy section is optional.
		pass
	except ConfigParser.NoOptionError, e:
		# not an error
		pass

	try:
		gSourceAccount = Account(cfparser.get('source', 'server'), cfparser.get('source', 'user'), cfparser.get('source', 'password'), pHost, pPort)
	except ConfigParser.NoSectionError, e:
		print "The configuration file has no 'source' section."
		print "The tool can't run without a source journal set." 
		print "Fix it and try again."
		sys.exit()
	except ConfigParser.NoOptionError, e:
		print "The configuration file is missing parameters for the source journal."
		print "The tool can't run without a source journal set." 
		print "Copy the sample config and try again."
		sys.exit()
	
	try:
		jrn = cfparser.get('source', 'communities').strip()
		if len(jrn) > 0:
			gSourceAccount.journal_list = re.split(', |,| ', jrn)
	except ConfigParser.NoOptionError, e:
		pass
		
	gMigrate = 0
	try:
		item = cfparser.get('settings', 'migrate')
		if item.lower() not in ['false', 'no', '0']:
			gMigrate = 1
	except ConfigParser.NoOptionError, e:
		pass

	gMigrateOwnOnly = 1
	try:
		item = cfparser.get('settings', 'migrate-community-posts-by-others')
		if item.lower() in ['true', 'yes', '1']:
			gMigrateOwnOnly = 0
	except ConfigParser.NoOptionError, e:
		pass
		
	gMigrationTags = []
	try:
		item = cfparser.get('settings', 'migrate-these-tags')
		if len(item) > 0: gMigrationTags = re.split(', |,| ', item)
	except ConfigParser.NoOptionError, e:
		pass

	gDestinationAccount = None
	if gMigrate:
		try:
			gDestinationAccount = Account(cfparser.get('destination', 'server'), cfparser.get('destination', 'user'), cfparser.get('destination', 'password'), pHost, pPort)
		except ConfigParser.NoSectionError, e:
			print "No destination journal specified in the config file; not migrating."
			gMigrate = 0
		except ConfigParser.NoOptionError, e:
			print "The configuration file is missing parameters for the destination journal."
			print "We can't migrate without knowing the information for the destination." 
			print "Turning migration off."
			gMigrate = 0
		try:
			jrn = cfparser.get('destination', 'communities').strip()
			if len(jrn) > 0: gDestinationAccount.journal_list = re.split(', |,| ', jrn)
		except ConfigParser.NoOptionError, e:
			pass


	gGenerateHtml = 1
	try:
		item = cfparser.get('settings', 'generate-html')
		if item.lower() in ['false', 'no', '0']:
			gGenerateHtml = 0
	except ConfigParser.NoOptionError, e:
		pass

#-------------------------------------------------------------------------------
# html generation
# poor man's html template; for generating correct html

doctype = u"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        "http://www.w3.org/TR/html4/loose.dtd">"""
# substitution variables are: JournalName, Subject
tmpl_start_jour = u'<html>\n<head>\n<meta http-equiv="content-type" content="text-html; charset=UTF-8" />\n<title>%s : %s</title></head>\n<body>\n'
# template start, subject only
tmpl_start_nojour = u'<html>\n<head>\n<meta http-equiv="content-type" content="text-html; charset=UTF-8" />\n<title>%s</title></head>\n<body>\n'
tmpl_end = u"</body>\n</html>"

userpattern = re.compile(r'<lj user="([^"]*)">')
commpattern = re.compile(r'<lj comm="([^"]*)">')

# hackity hack to make this global
indexEntries = []
entryprops = ['journalname', 'subject', 'eventtime', 'itemid', 'GroupMask', 'SecurityMode']

class Entry(object):
	def __init__(self, dict, username, journalname=None):
		self.username = username
		if journalname:
			self.journalname = journalname
		else:
			self.journalname = username
		for k in dict.keys():
			if type(dict[k]) == types.DictType:
				self.__dict__[k] = {}
				for j in dict[k].keys():
					self.__dict__[k][j] = convertBinary(dict[k][j])
			else:
				self.__dict__[k] = convertBinary(dict[k])
		self.comments = []
		self.commentids = {}
		
	def addComment(self, comment):
		self.commentids[comment.id] = comment
		
	def buildCommentTree(self):
		kys = self.commentids.keys()
		kys.sort()
		for k in kys:
			comment = self.commentids[k]
			if hasattr(comment, 'parentid') and len(comment.parentid) > 0 and self.commentids.has_key(comment.parentid):
				self.commentids[comment.parentid].addChild(comment)
			else:
				self.comments.append(comment)
	
	def getStringAttribute(self, attr):
		if not hasattr(self, attr):
			return ""
		item = getattr(self, attr)
		if type(item) in [types.IntType, types.LongType, types.FloatType]:
			return str(item)
		if type(item) == types.UnicodeType:
			return item
		return unicode(item, 'utf-8', 'replace')
		
	def getProperties(self):
		if hasattr(self, 'props') and type(self.props) == type({}):
			return self.props
		return {}

	def emit(self, path, groupmap={}):
		if not hasattr(self, 'itemid'):
			ljmLog("No item ID found in entry. Skipping: %s" % entry)
			return
		
		properties = self.getProperties()

		if hasattr(self, 'subject'):
			subject = self.getStringAttribute('subject')
			subject = userpattern.sub(r'<b><a href="http://\1.%s/"><img src="http://stat.livejournal.com/img/userinfo.gif" alt="[info]" width="17" height="17" style="vertical-align: bottom; border: 0;" />\1</a></b>' % gSourceAccount.site, subject)
			subject = commpattern.sub(r'<b><a href="http://community.%s/\1/"><img src="http://stat.livejournal.com/img/community.gif" alt="[info]" width="16" height="16" style="vertical-align: bottom; border: 0;" />\1</a></b>' % gSourceAccount.site, subject)
		else:
			subject = "(No Subject)"
		
		result = doctype + tmpl_start_jour % (self.journalname, subject)

		if properties.has_key('picture_keyword'):
			kw = properties['picture_keyword']
			if type(kw) == types.InstanceType:
				kw = kw.data.decode('utf-8', 'replace')
		else:
			kw = 'default'
		if gSourceAccount.userPictHash.has_key(kw):
			picpath = gSourceAccount.userPictHash[kw].replace(self.journalname, '..')
			result = result + u'<div id="picture_keyword" style="float:left; margin: 5px;"><img src="%s" alt="%s" title="%s" /></div>\n' % (picpath, kw, kw)
		else:
			result = result + u'<div id="picture_keyword"><b>Icon:</b> %s</div>\n' % (unicode(kw, 'utf-8', 'replace'), )

		for tag in entryprops:
			if self.__dict__.has_key(tag):
				attribute = self.getStringAttribute(tag)
				result = result + '<div id="%s"><b>%s:</b> %s</div>\n' % (tag, tag, attribute)

		if properties.has_key('current_mood'):
			result = result + '<div id="current_mood"><b>Mood:</b> %s</div>\n' % (properties['current_mood'], )
		if properties.has_key('current_music'):
			result = result + '<div id="current_music"><b>Music:</b> %s</div>\n' % (unicode(properties['current_music'], 'utf-8', 'replace'), )
		if properties.has_key('taglist'):
			result = result + '<div id="taglist"><b>Tags:</b> %s</div>\n' % (unicode(properties['taglist'], 'utf-8', 'replace'), )
		
		if hasattr(self, 'security'):
			security = self.getStringAttribute('security')
			if security == 'usemask':
				filter = int(self.getStringAttribute('allowmask'))
				result = result + '<div id="filter">'
				if filter == 1:
					result = result + "<b>Friends-locked</b><br />\n"
				else:
					fgrp = groupmap.get(filter, None)
					if fgrp:
						result = result + "<b>Filtered:</b> %s<br />\n" % (fgrp.get('name', 'unnamed group'), )
					else:
						result = result + "<b>Filtered:</b> friend group deleted; id was %d<br />\n" % filter
				result = result + '</div>'
			
		if hasattr(self, 'event'):
			result = result + '<br clear="left" />\n'
			content = self.getStringAttribute('event')
			if not properties.has_key('opt_preformatted'):
				content = content.replace("\n", "<br />\n");
			content = userpattern.sub(r'<b><a href="http://\1.%s/"><img src="http://stat.livejournal.com/img/userinfo.gif" alt="[info]" width="17" height="17" style="vertical-align: bottom; border: 0;" />\1</a></b>' % gSourceAccount.site, content)
			content = commpattern.sub(r'<b><a href="http://community.%s/\1/"><img src="http://stat.livejournal.com/img/community.gif" alt="[info]" width="16" height="16" style="vertical-align: bottom; border: 0;" />\1</a></b>', content)
	
			result = result + '\n<br /><div id="Content">%s</div>\n' % (content, )
			
		# emit comments
		self.buildCommentTree()
		for c in self.comments:
			result = result + "<hr />\n"
			result = result + c.emit().decode('utf-8', 'replace')
	
		result = result + tmpl_end
		
		fname = '%05d.html' % int(self.itemid)
		fpath = os.path.join(path, fname)
		output = codecs.open(fpath, 'w', 'utf-8', 'replace')
		output.write(result)
		output.close()
		
		# and finally, add it to the index accumulator
		idxtext = '+ %s: <a href="%s">%s</a><br />' % (self.__dict__.get('eventtime', None), fname, subject)
		indexEntries.append(idxtext)

def emitIndex(htmlpath, forceIndex=0):
	fpath = os.path.join(htmlpath, 'index.html')
	if os.path.exists(fpath) and not forceIndex:
		return # bailing for now, to avoid the data loss bug
	result = tmpl_start_nojour % ("Journal Index", )
	result = result + '\n'.join(indexEntries)
	result = result + tmpl_end

	fpath = os.path.join(htmlpath, 'index.html')
	output = codecs.open(fpath, 'w', 'utf-8', 'replace')
	output.write(result)
	output.close()

class Comment(object):
	def __init__(self, dict):
		self.children = []
		self.user = 'None'
		self.subject = ''
		self.body = ''
		self.date = ''
		for k in dict.keys():
			self.__dict__[k] = convertBinary(dict[k])
	
	def addChild(self, child):
		self.children.append(child)

	def emit(self, indent=0):
		result = []
		
		result.append('<div class="comment" style="margin-left: %dem; border-left: 1px dotted gray; padding-top: 1em;">' % (3 * indent, ))
		result.append('<b>%s</b>: %s<br />' % (self.user, self.subject))
		result.append('<b>%s</b><br />' % self.date)
		result.append(self.body)
		result.append('</div>')
		
		for child in self.children:
			result.append(child.emit(indent + 1))
		
		return '\n'.join(result)

def convertBinary(item):
	if type(item) in [types.StringType, types.UnicodeType]:
		return item.encode('utf-8', 'replace')
	elif type(item) == types.InstanceType:
		return item.data.decode('utf-8', 'replace')
	return item

def recordLastSync(lastsync, lastmaxid):
	f = gSourceAccount.openMetadataFile('last_sync', 0)
	f.write("%s\n" % lastsync)
	f.write("%s\n" % lastmaxid)
	f.close()

def recordEntryHash(entry_hash):
	f = gSourceAccount.openMetadataFile('entry_correspondences.hash', 0)
	pickle.dump(entry_hash, f)
	f.close()
		
def fetchItem(item):
	global errors, gAllEntries, newentries
	entry = None
	keepTrying = 3
	while keepTrying:
		try:
			itemid = item['item']
			if itemid.startswith('L-') or itemid.startswith('C-'):
				itemid = itemid[2:]

			entry = gSourceAccount.getOneEvent(itemid)
			if not entry:
				ljmLog("Source returned unexpected result when queried for item %s" % (item['item']))
				return None
			writedump(gSourceAccount.journal, item['item'], 'entry', entry)
			entry['event'] = convertBinary(entry['event'])

			if gGenerateHtml:
				eobj = Entry(entry, gSourceAccount.user, gSourceAccount.journal)
				gAllEntries[itemid] = eobj
			newentries += 1
			keepTrying = 0

		except socket.gaierror, e:
			ljmException("Socket error. Double-check your account information, and your net connection.", e)
			keepTrying = 0
		except xmlrpclib.ProtocolError, e:
			ljmException("recoverable; retrying:", e)
			keepTrying = keepTrying - 1
		except exceptions.KeyboardInterrupt, e:
			keepTrying = 0
			# TODO cleanup
			sys.exit()
		except exceptions.Exception, x:
			ljmException("fetching item %s; retrying" % item['item'], x)
			errors += 1
			keepTrying = 0
	return entry

#-------------------------------------------------------------------------------
# The migration function.

def synchronizeJournals(migrate = 0, retryMigrate = 0):
	""" This method is an embarrassment. Refactor to make it much smaller.
	"""
	ljmLog("Fetching journal entries for: %s" % gSourceAccount.journal)
	if not os.path.exists(gSourceAccount.journal):
		os.makedirs(gSourceAccount.journal)
		ljmLog("Created subdirectory: %s" % gSourceAccount.journal)

	global gAllEntries, errors, newentries, gMigrationTags  # HACK

	gAllEntries = {}
	errors = 0
	migrationCount = 0
	newentries = 0
	commentsBy = 0

	try:
		ljmLog("recording friends")
		frnds = gSourceAccount.getfriends()
		f = gSourceAccount.openMetadataFile('friends.meta', 0)
		pickle.dump(frnds, f)
		f.close()
	except:
		pass

	try:
		ljmLog("recording custom friend groups")
		grps = gSourceAccount.getfriendgroups()		
		groupmap = {}
		for g in grps.get('friendgroups'):
			groupmap[int(math.pow(2, int(g['id'])))] = g
		f = gSourceAccount.openMetadataFile('friendgroups.meta', 0)
		pickle.dump(groupmap, f)
		f.close()
		gSourceAccount.groupmap = groupmap
	except:
		pass
	
	lastsync = ""
	lastmaxid = 0
	try:
		f = gSourceAccount.readMetadataFile("last_sync")
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
	
	# aaaand ignore all this if we're retrying the migration
	if retryMigrate:
		lastsync = ""
		lastmaxid = 0

	try:
		f = gSourceAccount.readMetadataFile('entry_correspondences.hash', 0)
		entry_hash = pickle.load(f)
		f.close()
		test = entry_hash.keys()
		test.sort()
		if type(test[0]) == types.IntType:
			foo = {}
			foo[gSourceAccount.user] = entry_hash
			entry_hash = foo
	except:
		entry_hash = {}
		
	if not entry_hash.has_key(gSourceAccount.journal):
		entry_hash[gSourceAccount.journal] = {}
		
	considerTags = (gMigrationTags != None) and (len(gMigrationTags) > 0)
		
	while 1:
		syncitems = gSourceAccount.getSyncItems(lastsync)
		if len(syncitems) == 0:
			break
		for item in syncitems:
			if item['item'][0] == 'L':
				ljmLog("Fetching journal entry %s (%s)" % (item['item'], item['action']))
				entry = fetchItem(item)
				if not entry: continue
				
				# pulling this out into stages to make the logic clearer
				# only migrate if we have the option set, if we have a destination account, AND we have an entry to move
				migrate = (migrate and gDestinationAccount and entry)
				# if the entry has no poster key, it's a personal journal. always migrate
				# if the option to migrate only our own posts is set, we need to consider the poster...
				if entry and entry.has_key('poster'):
					if gMigrateOwnOnly:
						# and set the flag only if we're the original poster
						migrate = migrate and (entry['poster'] == gSourceAccount.user)
					else:
						# we prepend the post with a slug indicating who posted originally
						entry['event'] = (u'<p><b>Original poster: <i><a href="http://%s.%s/">%s</a></i></b><p>' % (entry['poster'],  gSourceAccount.site, entry['poster'])) + entry['event']
				elif considerTags and migrate:
					# This is a personal journal, but we're migrating only specific tags.
					# See if this entry has at least one of the target tags.
					migrate = 0
					tagstring = entry['props'].get('taglist', '')
					entrytags = re.split(', |,| ', tagstring)
					for t in entrytags:
						if t in gMigrationTags:
							migrate = 1
							break
				# end migration decision	
				
				if migrate:
					keepTrying = 5
					while keepTrying:
						try:
							if not entry_hash[gSourceAccount.journal].has_key(item['item'][2:]):
								ljmLog("    migrating entry to %s" % gDestinationAccount.journal)
								result = gDestinationAccount.postEntry(entry)
								entry_hash[gSourceAccount.journal][item['item'][2:]] = result.get('itemid', -1)
								recordEntryHash(entry_hash)
								migrationCount += 1
							elif item['action'] == 'update':
								ljmLog("   updating migrated entry in %s" % gDestinationAccount.journal)
								result = gDestinationAccount.editEntry(entry, entry_hash[gSourceAccount.journal][item['item'][2:]])
								migrationCount += 1
							keepTrying = 0
						except socket.gaierror, e:
							ljmException("Socket error. Double-check your account information, and your net connection.", e)
							keepTrying = 0
						except exceptions.KeyboardInterrupt, e:
							# TODO cleanup
							sys.exit()
						except xmlrpclib.Fault, e:
							try:
								code = int(e.faultCode)
							except:
								code = e.faultCode
							if code == 101:
								ljmLog("Fault reported is: %s; retrying" % e.faultString)
								keepTrying -= 1
							elif code == 205:
								# Client error: Unknown metadata: taglist
								matches = re.match(r'Client error: Unknown metadata: (\w+)', e.faultString)
								if matches:
									badprop = matches.group(1)
									del entry['props'][badprop]
									keepTrying -= 1
								else:
									ljmLog("Fault: %s; not retrying" % e.faultString)
									keepTrying = 0
							elif code == 302:
								ljmLog("Fault: %s; something is badly out of sync." % e.faultString)
								keepTrying = 0
							else:
								ljmException("Fault: "+e.faultString, e)
								keepTrying = 0
						except exceptions.Exception, x:
							ljmException("reposting item: %s" % item['item'], x)
							errors += 1
							keepTrying = 0
				# end if migrate
					
			elif item['item'].startswith('C-'):
				commentsBy += 1
				# I think there's no way to download the comment? buh?
				#print "Skipping comment %s by user (%s)" % (item['item'], item['action'])
			else:
				pprint.pprint(item)
			lastsync = item['time']
			recordLastSync(lastsync, lastmaxid)

	if migrationCount == 1:
		ljmLog("One entry migrated or updated on destination.")
	else:
		ljmLog("%d entries migrated or updated on destination." % (migrationCount, ))
	
	recordEntryHash(entry_hash)
	
	lastmaxid, newcomments = fetchNewComments(lastmaxid, lastsync, 0)	
	recordLastSync(lastsync, lastmaxid)
		
	if gGenerateHtml:
		generateHTML(gSourceAccount)
	
	ljmLog("Local archive complete!")

	if origlastsync:
		ljmLog("%d new entries, %d new comments (since %s),  %d new comments by user" % (newentries, newcomments, origlastsync, commentsBy))
	else:
		ljmLog("%d entries, %d comments, %d comments by user" % (newentries, newcomments, commentsBy))
	if errors > 0:
		ljmLog("%d errors" % errors)
# end synchronizeJournals

def generateHTML(gSourceAccount, forceIndex=0):
	global gAllEntries
	ljmLog("Now generating a simple html version of your posts + comments.")
	htmlpath = os.path.join(gSourceAccount.journal, 'html')
	if not os.path.exists(htmlpath):
		os.makedirs(htmlpath)
	
	ids = gAllEntries.keys()
	ids.sort(lambda x,y: int(x)-int(y))
	
	for id in ids:
		try:
			gAllEntries[id].emit(htmlpath, gSourceAccount.groupmap);
		except StandardError, e:
			ljmException("skipping building html for post %s because of error:" % id, e)
	try:
		emitIndex(htmlpath, forceIndex)
	except StandardError, e:
		ljmException("skipping html index generation because of error:" % id, e)
		
def fetchNewComments(lastmaxid, lastsync, refreshall=0):
	global gAllEntries
	try:
		f = gSourceAccount.readMetadataFile('comment.meta', 0)
		metacache = pickle.load(f)
		f.close()
	except:
		metacache = {}
	
	try:
		f = gSourceAccount.readMetadataFile('user.map', 0)
		usermap = pickle.load(f)
		f.close()
	except:
		usermap = {}
		
	ljmLog("Fetching journal comments for: %s" % gSourceAccount.journal)

	newcomments = 0
	
	maxid = lastmaxid
	while 1:
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
	
	f = gSourceAccount.openMetadataFile('comment.meta', 0)
	pickle.dump(metacache, f)
	f.close()
	
	f = gSourceAccount.openMetadataFile('user.map', 0)
	pickle.dump(usermap, f)
	f.close()
	
	newmaxid = maxid
	maxid = lastmaxid
	if gSourceAccount.user == gSourceAccount.journal:
		# hackity. haven't yet figured out how to get community comments
		while 1:
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
					'state': metacache.get(id, {}).get('state', ''),
				}
				if usermap.has_key(c.getAttribute("posterid")):
					comment["user"] = usermap[c.getAttribute("posterid")]

				path = os.path.join(gSourceAccount.journal, makeItemName(jitemid, 'entry'))
				if not os.path.exists(path):
					os.makedirs(path)
				try:
					entry = xml.dom.minidom.parse(os.path.join(path, "comments.xml"))
				except:
					entry = xml.dom.minidom.getDOMImplementation().createDocument(None, "comments", None)

				found = 0
				for d in entry.getElementsByTagName("comment"):
					if int(d.getElementsByTagName("id")[0].firstChild.nodeValue) == id:
						found = 1
						break

				if refreshall or not found:
					if gAllEntries.has_key(jitemid):
						cmt = Comment(comment)
						gAllEntries[jitemid].addComment(cmt)
					entry.documentElement.appendChild(createxml(entry, "comment", comment))
					
					f = codecs.open(os.path.join(path, "comments.xml"), "w", "UTF-8")
					entry.writexml(f)
					f.close()
					
					newcomments += 1

				if id > maxid:
					maxid = id
			if maxid >= newmaxid:
				break

	return (maxid, newcomments)
	# end fetch comments

	

#-------------------------------------------------------------------------------

def main(options):
	global gAllEntries
	fetchConfig()

	firstRunForAccount = 0
	if not os.path.exists(gSourceAccount.user):
		os.makedirs(gSourceAccount.user)
		print "Created subdirectory: %s" % gSourceAccount.user
		firstRunForAccount = 1
	
	path = gSourceAccount.metapath()
	if not os.path.exists(path):
		os.makedirs(path)
	gSourceAccount.runlog = codecs.open(os.path.join(path, "ljmigrate.log"), 'a', 'utf-8', 'replace')
	ljmLog("----------\nljmigrate run started: %s" % time.asctime())
	ljmLog("Version: %s" % __version__)
	
	dontFetchImageData = not options.userPicsOnly and options.skipUserPics
	
	gSourceAccount.makeSession()

	if options.commentsOnly and not firstRunForAccount:
		# TODO note repetition with regenhtml option handling; refactor
		gAllEntries = gSourceAccount.readAllEntryFiles()
		fetchNewComments(0, '', 1)
		gSourceAccount.readGroupMap()
		generateHTML(gSourceAccount, 1)
		endLogging()
		return
	
	gSourceAccount.fetchUserPics(dontFetchImageData)
	if options.userPicsOnly and not firstRunForAccount:
		endLogging()
		return
		
	if not options.commsOnly:
		synchronizeJournals(gMigrate, options.retryMigrate)
	
	if gDestinationAccount:
		accounts = map(None, gSourceAccount.journal_list, gDestinationAccount.journal_list)
		for pair in accounts:
			gSourceAccount.journal = pair[0]
			if pair[1]:
				gDestinationAccount.journal = pair[1]
				synchronizeJournals(1, options.retryMigrate)
			else:
				synchronizeJournals(0, options.retryMigrate)
	else:
		for comm in gSourceAccount.journal_list:
			gSourceAccount.journal = comm
			synchronizeJournals(0, options.retryMigrate)
			
	if options.regenhtml:
		gSourceAccount.readGroupMap()
		gAllEntries = gSourceAccount.readAllEntryFiles()
		generateHTML(gSourceAccount, 1)
	
	endLogging()
	
	
		
def nukeall(options):
	# note copy and pasted code blocks: refactor
	try:
		cfparser = ConfigParser.SafeConfigParser()
	except StandardError, e:
		cfparser = ConfigParser.ConfigParser()
	try:
		cfparser.readfp(open(options.configFile))
	except StandardError, e:
		print "Problem reading config file: %s" % str(e)
		sys.exit()
	
	pHost = None
	pPort = None
	try:
		pHost = cfparser.get('proxy', 'host')
		pPort = cfparser.get('proxy', 'port')
	except ConfigParser.NoSectionError, e:
		# not an error, because the proxy section is optional.
		pass
	except ConfigParser.NoOptionError, e:
		# not an error
		pass

	try:
		nukedAccount = Account(cfparser.get('nuke', 'server'), cfparser.get('nuke', 'user'), cfparser.get('nuke', 'password'), pHost, pPort)
	except StandardError, e:
		print "No account set up for nuking. Discretion is the better part of valor."
		sys.exit()

	try:
		jrn = cfparser.get('nuke', 'community').strip()
		nukedAccount.journal = jrn
	except ConfigParser.NoOptionError, e:
		pass

	print "NUKING ALL ENTRIES IN %s (%s)" % (nukedAccount.journal, nukedAccount.host)
	confirm = raw_input('Are you sure? [n/Y] ')
	if confirm != 'Y':
		print "Safe choice."
		sys.exit()
	confirm = raw_input('Are you really REALLY sure?\nAll entries for %s/%s will be gone. [n/Y] ' % (nukedAccount.host, nukedAccount.journal))
	if confirm != 'Y':
		print "Safe choice."
		sys.exit()
	
	print "Okay. Nuking all entries."
	
	lastsync = ""
	deleted = 0
	errors = 0
	while 1:
		syncitems = nukedAccount.getSyncItems(lastsync)
		if len(syncitems) == 0:
			break
		for item in syncitems:
			if item['item'][0] == 'L':
				print "Deleting journal entry %s" % (item['item'], )
				nukedAccount.deleteEntry(item['item'][2:])
				deleted += 1
			lastsync = item['time']
	print "Deleted %d items." % (deleted, )
	

def version():
	print "ljmigrate.py version", __version__
	sys.exit();
	
	
if __name__ == '__main__':
	usage = "usage: %prog [options]"
	version = "%prog " + __version__
	parser = OptionParser(usage=usage, version=version)
	
	parser.add_option('-r', '--retry', action='store_true', dest='retryMigrate', default=0,
		help="run through all posts on source, re-trying to migrate posts that weren't migrated the first time")
	parser.add_option('-u', '--user-pics-skip', action='store_true', dest='skipUserPics', default=0,
		help="don't back up icons/userpics this run")
	parser.add_option('-c', '--communities-only', action='store_true', dest='commsOnly', default=0,
		help="migrate/archive *only* communities")
	parser.add_option('-n', '--nuke', action='store_true', dest='nuke',
		help="delete ALL posts in the specified account; see README for details")
	parser.add_option('-p', '--user-pics-only', action='store_true', dest='userPicsOnly', default=0,
		help="just back up user pics")
	parser.add_option('-g', '--regenerate-html', action='store_true', dest='regenhtml', default=0,
		help="regenerate all the html files")
	parser.add_option('--comments-only', action='store_true', dest='commentsOnly', default=0,
		help="re-fetch all comments, skipping posts and other data")
	parser.add_option('-f', '--config-file', action='store', type='string', dest='configFile', default=configpath,
		help="specify location of config file") 

	(options, args) = parser.parse_args()

	if options.nuke:
		nukeall(options)
	else:
		main(options)

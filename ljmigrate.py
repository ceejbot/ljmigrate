#!/usr/bin/env python

"""
Based on ljdump; original ljdump license & header in LICENCE.text.
Extensive modifications by antennapedia.
Version 1.3
3 August 2007

BSD licence mumbo-jumbo to follow. By which I mean, do what you want.s
See README.text for documentation.
"""

import codecs
import exceptions
import getopt
import imghdr
import md5
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

__version__ = '1.3 070805k Sat Aug 11 16:27:42 PDT 2007'
__author__ = 'Antennapedia'
__license__ = 'BSD license'

configpath = "ljmigrate.cfg"

# hackity hack
global gSourceAccount, gDestinationAccount, gMigrate, gGenerateHtml
userPictHash = {}

# lj's time format: 2004-08-11 13:38:00
ljTimeFormat = '%Y-%m-%d %H:%M:%S'

def parsetime(input):
	try:
		return time.strptime(input, ljTimeFormat)
	except ValueError, e:
		#print e
		return ()

class Account(object):

	def __init__(self, host="", user="", password=""):
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
		self.server_proxy = xmlrpclib.ServerProxy(self.host+"/interface/xmlrpc")
		self.session = ""
		self.journal = user
		self.journal_list = []
	
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
		return e['events'][0]
		
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
		
	def fetchUserPics(self):
		log("Fetching new userpics for: %s" % self.user)
	
		r = self.getUserPics()
		userpics = {}
		for i in range(0, len(r['pickws'])):
			userpics[str(r['pickws'][i])] = r['pickwurls'][i]
		#userpics = dict(zip(r['pickws'], r['pickwurls']))
		userpics['default'] = r['defaultpicurl']

		try:
			fp = self.readMetadataFile("userpics.xml")
			string = fp.read()
			string = string.encode("utf-8", "replace")
			iconXML = xml.dom.minidom.parseString(string)
			userpictypes = {}
			for p in iconXML.getElementsByTagName("userpic"):
				key = p.getAttribute('keyword')
				type = p.getAttribute('type')
				userpictypes[key] = type
		except Exception, e:
			#exception("wtf", e)
			userpictypes = {}

		path = os.path.join(self.user, "userpics")
		if not os.path.exists(path):
			os.makedirs(path)
		f = self.openMetadataFile("userpics.xml")
		
		f.write('<?xml version="1.0" encoding="utf-8" ?>\n')
		f.write("<userpics>\n")
		for p in userpics:
			kwd = p.decode('utf-8', 'replace')
			
			if not userpictypes.has_key(kwd) or not os.path.exists(os.path.join(path, "%s.%s" % (canonicalizeFilename(kwd), userpictypes[kwd]))):
				log(u'    Getting pic for keywords "%s"' % kwd.encode('ascii', 'replace'))
				try:
					r = urllib2.urlopen(userpics[p])
					if r:
						data = r.read()
						type = imghdr.what(r, data)
						userpictypes[p] = type
						if p == "*":
							picfn = os.path.join(path, "default.%s" % type)
						else:
							picfn = os.path.join(path, "%s.%s" % (canonicalizeFilename(p), type))
						userPictHash[kwd] = unicode(picfn, 'utf-8', 'replace')
						picfp = open(picfn, 'w')
						picfp.write(data)
						picfp.close()
				except:
					pass
			f.write(u'<userpic keyword="%s" url="%s" type="%s" />\n' % (kwd, userpics[p], userpictypes.get(p, "")))

		f.write("</userpics>\n")
		f.close()

###

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


def fetchConfig():
	global gSourceAccount, gDestinationAccount, gMigrate, gGenerateHtml, gMigrateOwnOnly
	try:
		cfparser = ConfigParser.SafeConfigParser()
	except StandardError, e:
		cfparser = ConfigParser.ConfigParser()

	try:
		cfparser.readfp(open(configpath))
	except StandardError, e:
		print "Problem reading config file: %s" % str(e)
		sys.exit()
	
	try:
		gSourceAccount = Account(cfparser.get('source', 'server'), cfparser.get('source', 'user'), cfparser.get('source', 'password'))
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

	gDestinationAccount = None
	if gMigrate:
		try:
			gDestinationAccount = Account(cfparser.get('destination', 'server'), cfparser.get('destination', 'user'), cfparser.get('destination', 'password'))
		except ConfigParser.NoSectionError, e:
			print "No destination journal specified in the config file; not migrating."
			gMigrate = 0
		except ConfigParser.NoOptionError, e:
			print "The configuration file is missing parameters for the destination journal."
			print "We can't migrate without knowing the information for the destination." 
			print "Copy the sample config and try again."
			sys.exit()
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

###
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

	def emit(self, path):
		if not hasattr(self, 'itemid'):
			log("No item ID found in entry. Skipping: %s" % entry)
			return
		
		if hasattr(self, 'props'):
			properties = self.props
		else:
			properties = {}

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
		if userPictHash.has_key(kw):
			picpath = userPictHash[kw].replace(self.journalname, '..')
			result = result + u'<div id="picture_keyword" style="float:left; margin: 5px;"><img src="%s" alt="%s" title="%s" /></div>\n' % (picpath, kw, kw)
		else:
			result = result + u'<div id="picture_keyword"><b>Icon:</b> %s</div>\n' % (kw, )

		for tag in entryprops:
			if self.__dict__.has_key(tag):
				result = result + '<div id="%s"><b>%s:</b> %s</div>\n' % (tag, tag, getattr(self, tag))

		if properties.has_key('current_mood'):
			result = result + '<div id="current_mood"><b>Mood:</b> %s</div>\n' % (properties['current_mood'], )
		if properties.has_key('current_music'):
			result = result + '<div id="current_music"><b>Music:</b> %s</div>\n' % (properties['current_music'], )
		if properties.has_key('taglist'):
			result = result + '<div id="taglist"><b>Tags:</b> %s</div>\n' % (properties['taglist'], )
		
		if hasattr(self, 'event'):
			result = result + '<br clear="left" />\n'
			content = self.getStringAttribute('event')
			if not self.props.has_key('opt_preformatted'):
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

def emitIndex(htmlpath, firstTime):
	fpath = os.path.join(htmlpath, 'index.html')
	if os.path.exists(fpath):
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
	global errors, allEntries, newentries
	entry = None
	keepTrying = 3
	while keepTrying:
		try:
			entry = gSourceAccount.getOneEvent(item['item'][2:])
			writedump(gSourceAccount.journal, item['item'], 'entry', entry)
			entry['event'] = convertBinary(entry['event'])

			if gGenerateHtml:
				eobj = Entry(entry, gSourceAccount.user, gSourceAccount.journal)
				allEntries[item['item'][2:]] = eobj
			newentries += 1
			keepTrying = 0

		except socket.gaierror, e:
			exception("Socket error. Double-check your account information, and your net connection.", e)
			keepTrying = 0
		except xmlrpclib.ProtocolError, e:
			exception("recoverable; retrying:", e)
			keepTrying = keepTrying - 1
		except exceptions.KeyboardInterrupt, e:
			keepTrying = 0
			# TODO cleanup
			sys.exit()
		except exceptions.Exception, x:
			exception("fetching item %s; retrying" % item['item'], x)
			errors += 1
			keepTrying = 0
	return entry

		
def synchronizeJournals(migrate = 0):
	log("Fetching journal entries for: %s" % gSourceAccount.journal)
	if not os.path.exists(gSourceAccount.journal):
		os.makedirs(gSourceAccount.journal)
		log("Created subdirectory: %s" % gSourceAccount.journal)

	global allEntries, errors, newentries  # HACK

	allEntries = {}
	errors = 0
	migrationCount = 0
	newentries = 0
	newcomments = 0
	commentsBy = 0
	
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
		
	while 1:
		syncitems = gSourceAccount.getSyncItems(lastsync)
		if len(syncitems) == 0:
			break
		for item in syncitems:
			if item['item'][0] == 'L':
				log("Fetching journal entry %s (%s)" % (item['item'], item['action']))
				entry = fetchItem(item)
				
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
				
				if migrate:
					keepTrying = 5
					while keepTrying:
						try:
							if not entry_hash[gSourceAccount.journal].has_key(item['item'][2:]):
								log("    migrating entry to %s" % gDestinationAccount.journal)
								result = gDestinationAccount.postEntry(entry)
								entry_hash[gSourceAccount.journal][item['item'][2:]] = result.get('itemid', -1)
								recordEntryHash(entry_hash)
								migrationCount += 1
							elif item['action'] == 'update':
								log("   updating migrated entry in %s" % gDestinationAccount.journal)
								result = gDestinationAccount.editEntry(entry, entry_hash[gSourceAccount.journal][item['item'][2:]])
								migrationCount += 1
							keepTrying = 0
						except socket.gaierror, e:
							exception("Socket error. Double-check your account information, and your net connection.", e)
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
								log("Fault reported is: %s; retrying" % e.faultString)
								keepTrying -= 1
							elif code == 205:
								# Client error: Unknown metadata: taglist
								matches = re.match(r'Client error: Unknown metadata: (\w+)', e.faultString)
								if matches:
									badprop = matches.group(1)
									del entry['props'][badprop]
									keepTrying -= 1
								else:
									log("Fault: %s; not retrying" % e.faultString)
									keepTrying = 0
							elif code == 302:
								log("Fault: %s; something is badly out of sync." % e.faultString)
								keepTrying = 0
							else:
								exception("Fault: "+e.faultString, e)
								keepTrying = 0
						except exceptions.Exception, x:
							exception("reposting item: %s" % item['item'], x)
							errors += 1
							keepTrying = 0
					
			elif item['item'].startswith('C-'):
				commentsBy += 1
				#print "Skipping comment %s by user (%s)" % (item['item'], item['action'])
			else:
				pprint.pprint(item)
			lastsync = item['time']
			recordLastSync(lastsync, lastmaxid)

	if migrationCount == 1:
		log("One entry migrated or updated on destination.")
	else:
		log("%d entries migrated or updated on destination." % (migrationCount, ))
	
	recordEntryHash(entry_hash)

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
		
	log("Fetching journal comments for: %s" % gSourceAccount.journal)
	
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
	
	recordLastSync(lastsync, lastmaxid)

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
					'state': metacache[id]['state'],
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

				if found:
					log("Warning: downloaded duplicate comment id %d in jitemid %s" % (id, jitemid))
				else:
					if allEntries.has_key(jitemid):
						cmt = Comment(comment)
						allEntries[jitemid].addComment(cmt)
					entry.documentElement.appendChild(createxml(entry, "comment", comment))
					
					f = codecs.open(os.path.join(path, "comments.xml"), "w", "UTF-8")
					entry.writexml(f)
					f.close()
					
					newcomments += 1

				if id > maxid:
					maxid = id
			if maxid >= newmaxid:
				break
	
	lastmaxid = maxid
	
	recordLastSync(lastsync, lastmaxid)
		
	if gGenerateHtml:
		log("Now generating a simple html version of your posts + comments.")
		htmlpath = os.path.join(gSourceAccount.journal, 'html')
		if not os.path.exists(htmlpath):
			firstTime = 1
			os.makedirs(htmlpath)
		else:
			firstTime = 0
		
		ids = allEntries.keys()
		ids.sort()
		
		for id in ids:
			try:
				allEntries[id].emit(htmlpath);
			except StandardError, e:
				exception("skipping building html for post %s because of error:" % id, e)
		try:
			emitIndex(htmlpath, firstTime)
		except StandardError, e:
			exception("skipping html index generation because of error:" % id, e)
	
	log("Local archive complete!")

	if origlastsync:
		log("%d new entries, %d new comments (since %s),  %d new comments by user" % (newentries, newcomments, origlastsync, commentsBy))
	else:
		log("%d entries, %d comments, %d comments by user" % (newentries, newcomments, commentsBy))
	if errors > 0:
		log("%d errors" % errors)

def log(message):
	try:
		print message
	except:
		print "error logging message, of all things"
	try:
		gSourceAccount.runlog.write(message+"\n")
	except:
		pass

def exception(message, exc):
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


def main(retryMigrate = 0, communitiesOnly = 0, skipUserPics = 0):
	fetchConfig()

	if not os.path.exists(gSourceAccount.user):
		os.makedirs(gSourceAccount.user)
		print "Created subdirectory: %s" % gSourceAccount.user
		
	path = gSourceAccount.metapath()
	if not os.path.exists(path):
		os.makedirs(path)
	gSourceAccount.runlog = codecs.open(os.path.join(path, "ljmigrate.log"), 'a', 'utf-8', 'replace')
	log("----------\nljmigrate run started: %s" % time.asctime())
	log("Version: %s" % __version__)
	
	gSourceAccount.makeSession()
	if not skipUserPics:
		gSourceAccount.fetchUserPics()
	if not communitiesOnly:
		synchronizeJournals(gMigrate)
	
	if gDestinationAccount:
		accounts = map(None, gSourceAccount.journal_list, gDestinationAccount.journal_list)
		for pair in accounts:
			gSourceAccount.journal = pair[0]
			if pair[1]:
				gDestinationAccount.journal = pair[1]
				synchronizeJournals(1)
			else:
				synchronizeJournals(0)
	else:
		for comm in gSourceAccount.journal_list:
			gSourceAccount.journal = comm
			synchronizeJournals(0)
	
	log("Run ended normally: %s" % time.asctime())
	gSourceAccount.runlog.close()
	
	
		
def nukeall():
	try:
		cfparser = ConfigParser.SafeConfigParser()
	except StandardError, e:
		cfparser = ConfigParser.ConfigParser()
	try:
		cfparser.readfp(open(configpath))
	except StandardError, e:
		print "Problem reading config file: %s" % str(e)
		sys.exit()
	
	try:
		nukedAccount = Account(cfparser.get('nuke', 'server'), cfparser.get('nuke', 'user'), cfparser.get('nuke', 'password'))
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
	

def usage():
	print """ljmigrate.py
no options: archive & migrate posts from one LJ account to another
-n, --nuke : delete ALL posts in the specified account; see README for details
-r, --retry : run through all posts on source, re-trying to migrate posts that
              weren't migrated the first time
-c, --communities-only : migrate/archive *only* communities
-u, --user-pics-skip : don't back up user pics this run
-v, --version : print version
-h, --help : print this usage info"""
	version()


def version():
	print "ljmigrate.py version", __version__
	sys.exit();
	
	

if __name__ == '__main__':
	try:
		optlist, pargs = getopt.getopt(sys.argv[1:], 'nrhvcu', ['nuke', 'retry', 'help', 'version', 'communities-only', 'user-pics-skip'])
	except getopt.GetoptError, e:
		print e
		usage()

	options = {}
	for pair in optlist:
		options[pair[0]] = pair[1]
	
	if options.has_key('--help') or options.has_key('-h'):
		usage()

	if options.has_key('--version') or options.has_key('-v'):
		version()
	
	retryMigrate = 0
	if options.has_key('--retry') or options.has_key('-r'):
		retryMigrate = 1

	skipUserPics = 0
	if options.has_key('--user-pics-skip') or options.has_key('-u'):
		skipUserPics = 1

	commsOnly = 0
	if options.has_key('--communities-only') or options.has_key('-c'):
		commsOnly = 1

	if options.has_key('--nuke') or options.has_key('-n'):
		nukeall()
	else:
		main(retryMigrate, commsOnly, skipUserPics)


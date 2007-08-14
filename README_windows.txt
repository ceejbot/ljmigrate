# Windows instructions

First, you should see if LJ-SEC meets your needs, because it's probably
easier to use for Windows people:

	http://brown-betty.livejournal.com/284083.html
	
LJ-SEC can migrate personal journals, though not communities.
If you need to migrate communities, keep on reading!

## Install Python

First, you'll need to install the Python interpreter & libraries. 
A Windows installer is available on the official Python site:

	http://www.python.org/
	http://www.python.org/ftp/python/2.5.1/python-2.5.1.msi

Run the installer and follow the instructions.

## Unpack the zip file

You should be able to use the built-in Windows unarchiver to do this.
(What are some typical problems?)

## Configuration

Pitch the file named "ljmigrate.cfg", and make a copy of
"ljmigrate.cfg.windows". Rename it to be ljmigrate.cfg. This version of
the sample config uses Windows line endings, and is simpler to use.

Edit the config file using Notepad or a similar plain text file editor.
Follow the instructions in the main README for how to set it up.

## Running the tool

(This is where I need help writing this up.)

Start by reading through the Python Windows FAQ, which explains a lot:

	http://me.in-berlin.de/doc/python/faq/windows.html

Run through the steps described there to make sure you have python available
to run from a DOS command prompt.

Change directories so you're in the same folder as the script and the
config file. Run the script this way:

	python ljmigrate.py
	
Or if you're using command-line options, like this:

	python ljmigrate.py --communities-only
	

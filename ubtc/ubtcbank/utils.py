########################################################################
#                     Copyright (c) 2012 "Grazcoin"                    #
########################################################################
#
# This file is part of ubtcbank.com service
#
# ubtcbank is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public 
# License along with this program.
# If not, see <http://www.gnu.org/licenses/>.

import subprocess
import os
import time
import glob
from jsonrpc import ServiceProxy, JSONRPCException

BITCOINRPC="http://ubtcrpcuser:ubtctpcpassword@127.0.0.1:8332"

def execute(cmd_list):
        try:
            p = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out, err = p.communicate()
            return (out,err)
        except OSError:
            return(None,'Execution failed')

def timestamp():
   now = time.time()
   localtime = time.localtime(now)
   milliseconds = '%03d' % int((now - int(now)) * 1000)
   return time.strftime('%Y%m%d-%H%M%S.', localtime) + milliseconds

def shorten(s):
	if len(s) > 15:
		return s[:6]+'...'+s[-6:]
	else:
		return s

def addmultisigaddress(num, addr_list):
	bitcoin = ServiceProxy(BITCOINRPC)
	try:
		data=bitcoin.addmultisigaddress(int(num), addr_list)
	except JSONRPCException, e:
		return (False, "Error: %s" % e.error['message'])
	return (True, data)

def validateaddress(addr):
	bitcoin = ServiceProxy(BITCOINRPC)
	try:
		data=bitcoin.validateaddress(str(addr))
	except JSONRPCException, e:
		return (False, "Error: %s" % e.error['message'])
	return (data['isvalid'], data)

def createrawtransaction(in_array,out_set):
	bitcoin = ServiceProxy(BITCOINRPC)
	try:
		data=bitcoin.createrawtransaction(in_array,out_set)
	except JSONRPCException, e:
		return (False, "Error: %s" % e.error['message'])
	return data

def decoderawtransaction(rawtx):
	bitcoin = ServiceProxy(BITCOINRPC)
	try:
		data=bitcoin.decoderawtransaction(rawtx)
	except JSONRPCException, e:
		return (False, "Error: %s" % e.error['message'])
	return data

def signrawtransaction(rawtx, extended_in_list, keys_list):
	bitcoin = ServiceProxy(BITCOINRPC)
	try:
		data=bitcoin.signrawtransaction(rawtx, extended_in_list, keys_list)
	except JSONRPCException, e:
		return (False, "Error: %s" % e.error['message'])
	return data


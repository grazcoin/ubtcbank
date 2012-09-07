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

import urllib, urllib2
import json

min_conf=1

class BlockChainInfo():
    def __init__(self):
        pass

    def getreceivedbyaddress(self, addr, confirmations=min_conf):
        api='/q/getreceivedbyaddress/'+addr+'?confirmations='+str(confirmations)
        return self._curl_blockchaininfo(api=api, format='text')

    def addressbalance(self, addr, confirmations=min_conf):
        api='/q/addressbalance/'+addr+'?confirmations='+str(confirmations)
        return self._curl_blockchaininfo(api=api, format='text')

    def pubkeyaddr(self, addr, confirmations=min_conf):
        api='/q/pubkeyaddr/'+addr
        raw=self._curl_blockchaininfo(api=api, format='text')
	return raw[:130]

    def addrpubkey(self, pub):
	api1='/q/hashpubkey/'+pub
	hash=self._curl_blockchaininfo(api=api1, format='text')
	api2='/q/hashtoaddress/'+hash
	return self._curl_blockchaininfo(api=api2, format='text')

    def rawaddr(self, addr, confirmations=min_conf):
        api='/rawaddr/'+addr+'?confirmations='+str(confirmations)
        return self._curl_blockchaininfo(api=api)

    def multiaddr(self, addr_list, confirmations=min_conf):
        if len(addr_list)>0:
            api='/multiaddr?active='+addr_list[0]
            for addr in addr_list[1:]:
                api+='|'+addr
            return self._curl_blockchaininfo(api=api)

    def rawtx(self, txid):
        api='/rawtx/'+txid
        return self._curl_blockchaininfo(api=api)

    def unspent(self, addr):
	api='/unspent?address='+addr
	result=self._curl_blockchaininfo(api=api)
	if result==None:
		return {}
	return result

    def txid_from_index(self, index):
	api='/rawtx/'+str(index)
	result=self._curl_blockchaininfo(api=api)
	if result==None:
		return ''
	try:
	   return result['hash']
	except KeyError:
	    return ''

    def _curl_blockchaininfo(self, api, timeout=8, format='json'):
        BASE_URL = "https://blockchain.info"
        url = BASE_URL + api
        request = urllib2.Request(url)
	try:
        	response = urllib2.urlopen(request, timeout=timeout)
	except urllib2.HTTPError:
		return None
	if format == 'json':
        	return json.loads(response.read())
	else:
		return response.read()


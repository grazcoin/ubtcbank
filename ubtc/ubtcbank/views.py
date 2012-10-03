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

from ubtcbank.models import Key, SecureAddr, TxLog
from django.shortcuts import render_to_response, get_object_or_404
from utils import timestamp, addmultisigaddress, validateaddress, createrawtransaction, decoderawtransaction, signrawtransaction
from django.template import RequestContext
from aes import AES_Encrypt
import hashlib
from blockchaininfo import BlockChainInfo
from pyme import core
import logging

MAX_ATTEMPTS=10
MINIMAL_PINCODE_LEN=2
MAXIMAL_PINCODE_LEN=20
default_addr='1NmCwcu9whomTpniU7if7WkUnCDxt3z64R'
salt='uBTC'
BC=BlockChainInfo()
default_fee=0.0005
BTC_IN_SATOSHI=100000000
BackupKey='Grazcoin'

FORMAT = '%(asctime)-15s %(clientip)s %(message)s'
logging.basicConfig(format=FORMAT, datefmt='%Y-%m-%d %H:%M:%S', filename='/var/log/ubtcbank.log')
logger = logging.getLogger('ubtcbank')

def validate_token(request):
	token=request.COOKIES.get('token')
	secondary_addr=request.COOKIES.get('addr2')
	m = hashlib.sha256()
	m.update(salt+str(token))
	calculated_token_hash=m.hexdigest()
	try:
		key = Key.objects.get(btc_addr=secondary_addr)
	except Key.DoesNotExist:
		return (False, 'No such secondary address in database')
	if key.token_hash == calculated_token_hash:
		return (True, 'Identical token hash')
	else:
		return (False, 'Wrong token')

def backup_encrypt(text):
	plain = core.Data(str(text))
	cipher = core.Data()
	c = core.Context()
	c.set_armor(1)
	c.op_keylist_start(BackupKey, 0)
	r = c.op_keylist_next()
	c.op_encrypt([r], 1, plain, cipher)
	cipher.seek(0,0)
	return cipher.read()

def action(request, action_type):
	vars_dict={}
	token=request.COOKIES.get('token') 
	secondary_addr=request.COOKIES.get('addr2') 
	secondary_pub=request.COOKIES.get('pub2') 
	secure_addr=request.COOKIES.get('secure_addr') 
	primary_addr=request.COOKIES.get('addr1') 
	primary_pub='' 
	pincode='**********'
	vars_dict['fee']=default_fee
	vars_dict['token']=token
	vars_dict['secondary_addr']=secondary_addr
	vars_dict['secondary_pub']=secondary_pub
	vars_dict['primary_addr']=primary_addr
	vars_dict['secure_addr']=secure_addr
	
	if action_type == 'genkey':
		ip=None
		sec=None
		client=None
		token_hash=None
		action=None
		if request.method == 'POST':
			vars_dict['active_tab_done']=True
			try:
				secondary_pub=request.POST.get("pub", None)
				sec=request.POST.get("sec", None)
				secondary_addr=request.POST.get("addr", None)
				ip=request.META['HTTP_X_FORWARDED_FOR']
				client=request.META['HTTP_USER_AGENT']
				pincode=request.POST.get("pincode1", None)
			except KeyError:
				pass
			if len(pincode) < MINIMAL_PINCODE_LEN:
				return show_error(request, 'Minimal pincode length is '+str(MINIMAL_PINCODE_LEN))
			if len(pincode) > MAXIMAL_PINCODE_LEN:
				return show_error(request, 'Maximal pincode length is '+str(MAXIMAL_PINCODE_LEN))

			m = hashlib.sha256()
			m.update(salt+sec)
			token=m.hexdigest()
			m = hashlib.sha256()
			m.update(salt+str(token))
			token_hash=m.hexdigest()
			seen=False
			if secondary_pub != None:
				if secondary_addr != default_addr:
					try:
						key = Key.objects.get(pub_key=secondary_pub)
						seen = True
					except Key.DoesNotExist:
						key = Key.objects.create()
					key.active=True
					key.failed_attempts=0
					key.pub_key = secondary_pub
					key.btc_addr = secondary_addr
					key.generating_ip_addr = ip
					key.generating_client = client
					key.token_hash = token_hash
					enc_key=token+pincode
					a = AES_Encrypt(enc_key)
					key.encrypted_priv_key = a.aes_encrypt(sec)
					key.backup_encrypted_priv_key = backup_encrypt(sec)
					key.save()
					vars_dict['secondary_addr']=secondary_addr
					vars_dict['token']=token
				else:
					# default key warning:
					return show_error(request, 'Please do not use the default key')
				if seen == True:
					vars_dict['seen']=True
		else:
			vars_dict['active_tab_generator'] = True
		vars_dict['secondary_pub']=secondary_pub

	elif action_type == 'genaddr':
		vars_dict['active_tab_sign']=True
		if request.method == 'POST':
			# verify that token is valid
			(valid, msg) = validate_token(request)
			if not valid:
				return show_error(request, msg)
			try:
				primary_addr=request.POST.get("donePrimary", None)
				primary_pub=str(primary_addr) # assume the public key was given and not a BTC addr
			except KeyError:
				return show_error(request, 'Missing primary address')
			(valid,data)=validateaddress(primary_addr)
			if not valid:
				if not len(primary_addr)==130:
					return show_error(request, 'Invalid primary bitcoin address / pub key')
				else:
					pass # so indeed it was the public key
			addr_list=[]
			if primary_addr == None:
				return show_error(request, 'Empty primary address')
			if len(primary_pub) > 34: # a pub key was given. let's convert pub key to btc address
				primary_addr=BC.addrpubkey(primary_pub)
				if len(primary_addr) > 34:
					return show_error(request, 'Failed converting pub key to bitcoin address. Try other addresses.')
				
			if len(primary_pub) <= 34: # a bitcoin address was given. get the pub
				primary_pub=BC.pubkeyaddr(primary_addr)
				if len(primary_pub) < 130:
					return show_error(request,
						'Please enter pub key of primary key instead the key ' +
						'itself since primary address has no spent tx in the blockchain')
			addr_list.append(secondary_pub)
			addr_list.append(primary_pub)
			(result,secure_addr)=addmultisigaddress(2, addr_list)
			if result == False:
				return show_error(request, 'Failed calculating a secure address. Try other addresses.')
			vars_dict['primary_addr']=primary_addr
			vars_dict['primary_pub']=primary_pub
			vars_dict['secure_addr']=secure_addr

			try:   
				key = Key.objects.get(btc_addr=secondary_addr)
			except Key.DoesNotExist:
				return show_error(request, 'Key is not in database: '+str(secondary_addr))

			try:   
				secureaddr = SecureAddr.objects.get(secure_addr=secure_addr)
			except SecureAddr.DoesNotExist:
				secureaddr = SecureAddr.objects.create(secondary_addr=key)
				key.secureaddrs.add(secureaddr)
				key.save()

			secureaddr.secure_addr=secure_addr
			secureaddr.primary_addr=primary_addr
			secureaddr.primary_pub=primary_pub
			secureaddr.save()

	elif action_type == 'rawtx':
		vars_dict['active_tab_sign'] = True
		primary_addr=None
		primary_pub=None
		secondary_addr=None
		secondary_pub=None
		to_addr=None
		from_addr=None
		change_addr=None
		pincode=None
		amount=None
		fee=None
		if request.method == 'POST':
			# verify that token is valid
			(valid, msg) = validate_token(request)
			if not valid:
				return show_error(request, msg)
			try:
				primary_addr=request.POST.get("pay_prim_sign_addr", None)
				(valid,data)=validateaddress(primary_addr)
				if not valid:
					return show_error(request, 'The \"primary address\" is not a valid bitcoin address')
				secondary_addr=request.POST.get("pay_sign_addr", None)
				(valid,data)=validateaddress(secondary_addr)
				if not valid:
					return show_error(request, 'The \"secondary address\" is not a valid bitcoin address')
				to_addr=request.POST.get("pay_to_addr", None)
				(valid,data)=validateaddress(to_addr)
				if not valid:
					return show_error(request, 'The \"pay to address\" is not a valid bitcoin address')
				from_addr=request.POST.get("pay_from_addr", None)
				(valid,data)=validateaddress(from_addr)
				if not valid:
					return show_error(request, 'The \"from address\" is not a valid bitcoin address')
				change_addr=request.POST.get("pay_change_addr", None)
				(valid,data)=validateaddress(change_addr)
				if not valid:
					return show_error(request, 'The \"change address\" is not a valid bitcoin address')
				token=request.POST.get("pay_token", None)
				amount=request.POST.get("pay_amount", None)
				try:
					if float(amount)<=0 or float(amount)>=21000000:
						return show_error(request, 'Amount out of range')
				except ValueError:
					return show_error(request, 'Invalid amount')
				fee=request.POST.get("pay_fee", None)
				try:
					if float(fee)<=0 or float(fee)>=21000000:
						return show_error(request, 'Fee out of range')
				except ValueError:
					return show_error(request, 'Invalid fee')
				
				pincode=request.POST.get("pincode2", None)
				if pincode == None:
					return show_error(request, 'no pincode in POST request')
				if len(pincode) < MINIMAL_PINCODE_LEN:
					return show_error(request, 'Minimal pincode length is '+str(MINIMAL_PINCODE_LEN))
				if len(pincode) > MAXIMAL_PINCODE_LEN:
					return show_error(request, 'Maximal pincode length is '+str(MAXIMAL_PINCODE_LEN))
				ip=request.META['HTTP_X_FORWARDED_FOR']
				client=request.META['HTTP_USER_AGENT']
			except KeyError:
				pass

			vars_dict['secondary_addr']=secondary_addr
			vars_dict['to_addr']=to_addr
			vars_dict['from_addr']=from_addr
			vars_dict['change_addr']=change_addr
			vars_dict['pincode']=pincode
			vars_dict['amount']=amount
			vars_dict['fee']=fee
			# get encrypted priv key from sign_addr
			primary_pub=''
			secondary_pub=''
			try:
				key = Key.objects.get(btc_addr=secondary_addr)
				if key.active == False:
					return show_error(request, 'Key disabled due to repeating wrong pincode. Please generate key again.')
				encrypted_priv_key=key.encrypted_priv_key
				enc_key=token+pincode
				try:
					a = AES_Encrypt(enc_key)
					priv_key = a.aes_decrypt(encrypted_priv_key)
				except UnicodeDecodeError:
					key.failed_attempts += 1
					if key.failed_attempts >= MAX_ATTEMPTS:
						key.active = False
					key.save()
					return show_error(request, 'Wrong pincode attempt number: '+str(key.failed_attempts)+' out of '+str(MAX_ATTEMPTS))
				# retrieve pub keys for P2SH script
				secondary_pub=key.pub_key
				key.failed_attempts = 0
				key.save()
				unspent=BC.unspent(from_addr)
				in_array=[]
				extended_in_array=[]
				value=0
				if unspent.has_key('unspent_outputs'):
					for in_tx in unspent['unspent_outputs']:
						txid=str(BC.txid_from_index(in_tx['tx_index']))
						value+=int(in_tx['value'])
						in_array.append({"txid":txid, "vout":int(in_tx['tx_output_n'])})
						extended_in_array.append({"txid":txid, 
							"vout":int(in_tx['tx_output_n']), "scriptPubKey":str(in_tx['script'])})
				else:
					return show_error(request, 'No unspent outputs for address '+str(from_addr))
				change=float(value+0.0)/100000000-float(amount)-float(fee)
				if change > 0:
					# add change to tx only if it is non zero
					out_set={str(to_addr):float(amount),str(change_addr):change}
				else:
					out_set={str(to_addr):float(amount)}
				rawtx=createrawtransaction(in_array,out_set)

				try:   
					secureaddr = SecureAddr.objects.get(secure_addr=from_addr)
					primary_pub=secureaddr.primary_pub
				except SecureAddr.DoesNotExist:
					return show_error(request, 'Secure address is not in database: '+str(from_addr))

				jsonsignedrawtx=signrawtransaction(rawtx, extended_in_array, [priv_key, secondary_pub, primary_pub])
				#vars_dict['in_array']=extended_in_array
				#vars_dict['out_set']=out_set
				#vars_dict['rawtx']=rawtx
				#vars_dict['decodedrawtx']=decodedrawtx
				try:
					signedrawtx=jsonsignedrawtx['hex']
				except KeyError:
					signedrawtx='error parsing rawtx'
					return show_error(request, 'Error parsing rawtx')
				except TypeError, e:
					return show_error(request, str(e.error['message'])+': '+str(rawtx)+' '+str(extended_in_array)+' '+str([priv_key, secondary_pub, primary_pub]))
				#vars_dict['signedrawtx']=signedrawtx
				rawtx_output='bitcoind addmultisigaddress 2 \'[\"'+secondary_pub+'\",\"'+primary_pub+'\"]\'; bitcoind signrawtransaction '+signedrawtx+' \''+str(extended_in_array).replace('\'','\"')+'\''
				vars_dict['bitcoind_required_command']=rawtx_output
				txid='unknown-'+timestamp()
				#decodedsignedrawtx=decoderawtransaction(signedrawtx)
				#vars_dict['decodedsignedrawtx']=decodedsignedrawtx

				try:   
					txlog = TxLog.objects.get(txid=txid)
				except TxLog.DoesNotExist:
					txlog=TxLog.objects.create(from_addr=secureaddr)
					secureaddr.txlogs.add(txlog)
					secureaddr.save()

				txlog.to_addr=to_addr
				txlog.change_addr=change_addr
				txlog.amount=int(float(amount)*BTC_IN_SATOSHI)
				txlog.fee=int(float(fee)*BTC_IN_SATOSHI)
				txlog.generating_ip_addr=ip
				txlog.generating_client=client
				txlog.txid=txid
				txlog.signedrawtx=signedrawtx
				txlog.save()
				return render_to_response("keys/sign.html", vars_dict, context_instance=RequestContext(request))
			except Key.DoesNotExist:
				return show_error(request, 'Key for address '+str(secondary_addr)+' does not exist in database')
		else:
			pass	

		return show_error(request, 'POST data required')
	else:
		# action is not implpemented
		return show_error(request, 'action type '+action_type+' not implemented')

	# update pincode (**** if not present)
	vars_dict['pincode']=pincode
	if secondary_pub != None:
		vars_dict['secondary_pub']=secondary_pub
	if secondary_addr != None:
		vars_dict['secondary_addr']=secondary_addr
	if secure_addr != None:
		vars_dict['secure_addr']=secure_addr
	if primary_addr != None:
		vars_dict['primary_addr']=primary_addr

	response=render_to_response("brainwallet/add.html", vars_dict, context_instance=RequestContext(request))

        if secondary_pub != None:
                response.set_cookie("pub2",secondary_pub)
        if secondary_addr != None:
                response.set_cookie("addr2",secondary_addr)
        if token != None:
                response.set_cookie("token",token)
        if secure_addr != None:
                response.set_cookie("secure_addr",secure_addr)
        if primary_addr != None:
                response.set_cookie("addr1",primary_addr)

	return response

def cookies_export(request, type='text'):
	vars_dict={}
	token=request.COOKIES.get('token') 
	secondary_addr=request.COOKIES.get('addr2') 
	secondary_pub=request.COOKIES.get('pub2') 
	secure_addr=request.COOKIES.get('secure_addr') 
	primary_addr=request.COOKIES.get('addr1') 
	exported='{\"addr1\":"'+str(primary_addr)+'", "addr2":"'+str(secondary_addr)+'", "pub2":"'+str(secondary_pub)+'", "secure_addr":"'+str(secure_addr)+'", "token":"'+str(token)+'"}'
	vars_dict['exported']=exported
	if type=='text':
		return render_to_response("keys/export.html", vars_dict, context_instance=RequestContext(request))
	else:
		return render_to_response("keys/qrexport.html", vars_dict, context_instance=RequestContext(request))

def cookies_import(request):
	vars_dict={}
	return render_to_response("keys/import.html", vars_dict, context_instance=RequestContext(request))
	
def cookies_qrexport(request):
	return cookies_export(request, 'qr')
	
def genkey(request):
	return action(request, 'genkey')

def genaddr(request):
	return action(request, 'genaddr')

def pay(request):
	return action(request, 'pay')

def rawtx(request):
	return action(request, 'rawtx')

def show_error(request, msg):
	vars_dict={}
	vars_dict['error_msg']=msg
	d={}
	try:
		d['clientip']=request.META['HTTP_X_FORWARDED_FOR']
	except KeyError:
		d['clientip']='unknown'
	logger.error(msg, extra=d)
	return render_to_response("keys/error.html", vars_dict, context_instance=RequestContext(request))


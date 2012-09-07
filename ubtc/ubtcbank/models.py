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

from django.db import models

class KeyManager(models.Manager):
	def get(self, *args, **kwargs):
		return super(KeyManager, self).get(*args, **kwargs)
	def create(self, *args, **kwargs):
		return super(KeyManager, self).create(*args, **kwargs)

class SecureAddrManager(models.Manager):
	def get(self, *args, **kwargs):
		return super(SecureAddrManager, self).get(*args, **kwargs)
	def create(self, *args, **kwargs):
		return super(SecureAddrManager, self).create(*args, **kwargs)

class TxLogManager(models.Manager):
	def get(self, *args, **kwargs):
		return super(TxLogManager, self).get(*args, **kwargs)
	def create(self, *args, **kwargs):
		return super(TxLogManager, self).create(*args, **kwargs)




class Key(models.Model):
	pub_key = models.CharField(max_length=200)
	btc_addr = models.CharField(max_length=200)
	encrypted_priv_key = models.CharField(max_length=200)
	backup_encrypted_priv_key = models.CharField(max_length=800, default='unknown')
	token_hash = models.CharField(max_length=200)
	creation_time = models.DateTimeField('creation time', auto_now_add=True)
	last_used_time = models.DateTimeField('last used time', auto_now=True)
	failed_attempts = models.IntegerField('failed attempts', default=0)
	generating_ip_addr = models.IPAddressField(default='127.0.0.1')
	generating_client = models.CharField(max_length=200, default='unknown')
	active = models.BooleanField('active', default=True)
	secureaddrs = models.ManyToManyField("SecureAddr")
	objects = KeyManager()
	def __unicode__(self):
		return self.btc_addr

class SecureAddr(models.Model):
	primary_addr = models.CharField(max_length=200)
	primary_pub = models.CharField(max_length=200, default='unknown')
	secondary_addr = models.ForeignKey(Key)
	secure_addr = models.CharField(max_length=200)
	creation_time = models.DateTimeField('creation time', auto_now_add=True)
	balance = models.PositiveIntegerField(default=0) # for statistics only. updated externally.
	txlogs = models.ManyToManyField("TxLog")
	objects = SecureAddrManager()
	def __unicode__(self):
		return self.secure_addr


class TxLog(models.Model):
	from_addr = models.ForeignKey(SecureAddr)
	to_addr = models.CharField(max_length=200)
	change_addr = models.CharField(max_length=200)
	amount = models.PositiveIntegerField(default=0)
	fee = models.PositiveIntegerField(default=0)
	creation_time = models.DateTimeField('creation time', auto_now_add=True)
	generating_ip_addr = models.IPAddressField(max_length=200, default='127.0.0.1')
	generating_client = models.CharField(max_length=200, default='unknown')
	txid = models.CharField(max_length=200)
	signedrawtx = models.CharField(max_length=800, default='unknown')
	published = models.BooleanField('published', default=False) # for statistics only. updated externally.
	objects = TxLogManager()
	def __unicode__(self):
		return self.txid


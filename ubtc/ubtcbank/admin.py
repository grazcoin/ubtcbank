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

from django.contrib import admin
from ubtcbank.models import Key, SecureAddr, TxLog
from functools import partial
from django.forms import MediaDefiningClass

class ModelAdminWithForeignKeyLinksMetaclass(MediaDefiningClass):

    def __getattr__(cls, name):

        def foreign_key_link(instance, field):
            target = getattr(instance, field)
            return u'<a href="../../%s/%s/%d">%s</a>' % (
                target._meta.app_label, target._meta.module_name, target.id, unicode(target))

        if name[:8] == 'link_to_':
            method = partial(foreign_key_link, field=name[8:])
            method.__name__ = name[8:]
            method.allow_tags = True
            setattr(cls, name, method)
            return getattr(cls, name)
        raise AttributeError

class KeyAdmin(admin.ModelAdmin):
	list_display = ('btc_addr', 'active', 'failed_attempts', 'generating_client', 'generating_ip_addr', 
				'creation_time', 'last_used_time')
	search_fields=['btc_addr', 'pub_key', 'generating_client', 'generating_ip_addr', 'generating_client']
	list_filter = ('active', 'generating_client',)
admin.site.register(Key, KeyAdmin)

class SecureAddrAdmin(admin.ModelAdmin):
	__metaclass__ = ModelAdminWithForeignKeyLinksMetaclass
	list_display = ('secure_addr', 'primary_addr', 'link_to_secondary_addr', 'balance', 'creation_time')
	search_fields=['secure_addr', 'primary_addr', 'secondary_addr__btc_addr']
admin.site.register(SecureAddr, SecureAddrAdmin)

class TxLogAdmin(admin.ModelAdmin):
	__metaclass__ = ModelAdminWithForeignKeyLinksMetaclass
	list_display = ('txid', 'link_to_from_addr', 'to_addr', 'amount', 'fee', 'generating_client', 'generating_ip_addr', 
				'creation_time', 'published')
	search_fields=['txid', 'amount', 'from_addr__secure_addr', 'to_addr', 'fee', 
				'generating_ip_addr', 'generating_client']
admin.site.register(TxLog, TxLogAdmin)

import logging
import asyncio

from msldap.commons.url import MSLDAPURLDecoder
from msldap.ldap_objects import MSADGPO


class Ldap:
    def __init__(self, url, gpo_id, domain):
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dn = 'CN={' + gpo_id + '}},CN=Policies,CN=System,{}'.format(self.domain_dn)
        conn_url = MSLDAPURLDecoder(url)
        self.ldap_client = conn_url.get_client()

    async def connect(self):
        _, err = await self.ldap_client.connect()
        if err is not None:
            logging.error("LDAP connection failed")
            return False
        return True

    async def get_attribute(self, attribute):
        async for gpo in self.ldap_client.get_object_by_dn(self.dn, expected_class=MSADGPO):
            try:
                return getattr(gpo, attribute)
            except Exception as e:
                return False

    async def update_attribute(self, attribute, value):
        _, err = await self.ldap_client.modify_object_by_dn(self.dn, {
            attribute: [('replace', [value])]
        })

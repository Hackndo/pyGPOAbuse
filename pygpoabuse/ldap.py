import logging
import asyncio

from msldap.commons.factory import LDAPConnectionFactory
from msldap.ldap_objects import MSADGPO


class Ldap:
    def __init__(self, url, gpo_id, domain):
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dn = 'CN={' + gpo_id + '}},CN=Policies,CN=System,{}'.format(self.domain_dn)
        conn_url = LDAPConnectionFactory.from_url(url)
        self.ldap_client = conn_url.get_client()

    async def connect(self):
        _, err = await self.ldap_client.connect()
        if err is not None:
            logging.error("LDAP connection failed")
            return False
        return True

    async def get_attribute(self, attribute):
        async for gpo, err in self.ldap_client.get_object_by_dn(self.dn, expected_class=MSADGPO):
            try:
                return getattr(gpo, attribute)
            except Exception as e:
                return "An error occurred", str(e)

    async def update_attribute(self, attribute, value, old_value=None):
        if old_value is None:
            action = 'add'
        else:
            action = 'replace'
        _, err = await self.ldap_client.modify(self.dn, {
            attribute: [(action, [value])]
        })
        if err is not None:
            logging.debug("Error while updating {}".format(attribute))
            logging.debug(err)

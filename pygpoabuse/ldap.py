import logging
import asyncio

from msldap.commons.factory import LDAPConnectionFactory
from msldap.ldap_objects import MSADGPO


async def find_gpo_id_by_name(url, domain, name):
    """Return the raw GUID (without braces) of the GPO whose displayName matches *name*, or None."""
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        logging.debug(f"LDAP connection failed during GPO name resolution: {err}")
        return None
    async for gpo, err in ldap_client.get_all_gpos():
        if err is not None:
            logging.debug(f"Error fetching GPOs: {err}")
            return None
        if gpo is None:
            continue
        if getattr(gpo, 'displayName', None) == name:
            cn = getattr(gpo, 'cn', None)
            if cn:
                return cn.strip('{}')
    return None


class Ldap:
    def __init__(self, url, gpo_id, domain):
        self.domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
        self.dn = f'CN={{{gpo_id}}},CN=Policies,CN=System,{self.domain_dn}'
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
            if err is not None:
                logging.debug(f"Error fetching {attribute}: {err}")
                return False
            try:
                return getattr(gpo, attribute)
            except AttributeError:
                return False
        return False

    async def update_attribute(self, attribute, value, old_value=None):
        if old_value is None:
            action = 'add'
        else:
            action = 'replace'
        _, err = await self.ldap_client.modify(self.dn, {
            attribute: [(action, value)]
        })
        if err is not None:
            logging.debug("Error while updating {}".format(attribute))
            logging.debug(err)

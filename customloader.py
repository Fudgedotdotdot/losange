import io
import zipfile
from pathlib import Path
import importlib
import importlib.machinery
import io
from pathlib import Path
import sys
import types
import zipfile
from zipfile import ZipFile, ZipInfo

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
                #print("[-] Module '%s' has not been found as loadable. Failing..." % fullname)
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



# Use this to debug imports that are not managed by our CustomLoader
import importlib.machinery
import sys

original_pathfinder = importlib.machinery.PathFinder

class LoggingLoaderWrapper:
    def __init__(self, original_loader):
        self.original_loader = original_loader

    def create_module(self, spec):
        return self.original_loader.create_module(spec) if hasattr(self.original_loader, 'create_module') else None

    def exec_module(self, module):
        print(f"[EXEC] Executing module: {module.__name__}")
        return self.original_loader.exec_module(module)

class LoaderTrackingPathFinder:
    @classmethod
    def find_spec(cls, fullname, path=None, target=None):
        spec = original_pathfinder.find_spec(fullname, path, target)
        if spec and spec.loader and hasattr(spec.loader, 'exec_module'):
            if spec.origin and spec.origin != 'built-in':
                if '.pyd' in spec.origin:
                    print(f"[PYD] {fullname} from {spec.origin}")
                else:
                    print(f"[IMPORT] {fullname} from {spec.origin}")
            spec.loader = LoggingLoaderWrapper(spec.loader)
        return spec

sys.meta_path.insert(0, LoaderTrackingPathFinder)


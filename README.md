# Losange


## Overview
**Losange** is based on naksyn's [Pyramid](https://github.com/naksyn/Pyramid) but uses a newer import class provided by operatorequals's [httpimport](https://github.com/operatorequals/httpimport) rather than the older *CFinder* from [EmPyre](https://github.com/EmpireProject/EmPyre) to load python packages from memory. 

## Requirements

- Python3.12 (tested with 3.12.7)
- Import errors with Python 3.13.2

## Features
- Load Python packages directly into memory.
- Dynamically write necessary dependencies to disk


The issue raised by naksyn's [blog](https://www.naksyn.com/edr%20evasion/2022/09/01/operating-into-EDRs-blindspot.html) about Pyramid was the need to write *pyd* files to disk, since they cannot be loaded from memory by Python. The solution provided by the tool is to write entire packages that use *pyd* files to disk. 

**Losange** manages dependencies dynamically, parsing the provided ZIP and only extracting *pyd* files to disk, not the entire package. The directory structure of the package on disk is still the same, but contains just these dependencies. See [Description](#description) for details. 


Additionally, when using the *pythonnet* library, certain external dependencies are required, such as *CLRLoader.dll* and *Python.Runtime.dll*. To simplify handling these dependencies, **Losange** provides functionality that allows the caller to specify the argument `dependencies_ext`. This argument accepts a list of dependencies, which Losange will extract directly from the ZIP archive.

```python
dependencies_ext=[".dll"]
importer = add_remote_bytes(
    zipname=''.join(random.choices(string.ascii_letters + string.digits, k=8)),
    zipbytes=zipbytes,
    dependencies_ext=dependencies_ext)
```

See [External Dependencies](#External-Dependencies) for details about how this feature works and necessary changes of library code for the in-memory import to work correctly.




## Installation
Simply clone the repository to get started:

```bash
git clone https://github.com/Fudgedotdotdot/losange.git
cd losange
```

Examples are provided in the `examples` directory. 

Providing your own packages is as easy as creating a virtual environment, installing the package, and archiving all the files in `site-packages`. 


```powershell
❯ py -3.12 -m venv .pythonnet
❯ pip install pythonnet
❯ cd .\.pythonnet\Lib\site-packages\
❯ Compress-Archive * -DestinationPath pythonnet.zip
❯ tar -tf .\pythonnet.zip | select -first 5
__pycache__/clr.cpython-312.pyc
cffi/__init__.py
cffi/_cffi_errors.h
cffi/_cffi_include.h
cffi/_embedding.h
...
```

## Description

By manipulating `sys.meta_path` and `sys.path`, we can make our loader be the first importer that Python will use to resolve packages. 


```python
def add_remote_bytes(zipname: str, zipbytes: bytes, dependencies_ext: list[str] = []):
    importer = CustomImporter(
        zipname,
        zipbytes,
        dependencies_ext
    )
    sys.meta_path.insert(0, importer) # making our importer first in the list
    sys.path.insert(0, str(Path(zipname).absolute())) # making the PathFinder importer search for dependencies in our fake path (zipname is the random package name)
```
By changing the order of `sys.meta_path`, we don't run into the issue of `PathFinder` attempting to load packages from disk before our ZIP archive. 

```python
[<__main__.CustomImporter object at 0x0000023D308596D0>, <class '_frozen_importlib.BuiltinImporter'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib_external.PathFinder'>]
```

And changing `sys.path` ensures that Python will search first in our random directory (our fake package path) for any dependencies. 


Enabling debugging with `LoaderTrackingPathFinder` shows that with our `sys` changes, Python loads the *cryptography* package from the archive, but fails (not shown) when importing *pyd* files and falls back to loading from our random directory. 

```powershell
[+] Extracted cryptography/__init__.py from archive. The module can be loaded!
[*] Metadata (__package__) set to cryptography : __filepath__ to ['izR72lIk/cryptography/'],  __name__ to cryptography for package cryptography
[+] Extracted cryptography/__about__.py from archive. The module can be loaded!
[*] Metadata (__package__) set to cryptography : __filepath__ to ['izR72lIk/cryptography/'],  __name__ to cryptography.__about__ for module cryptography.__about__
[+] Extracted cryptography/hazmat/__init__.py from archive. The module can be loaded!
[*] Metadata (__package__) set to cryptography.hazmat : __filepath__ to ['izR72lIk/cryptography/hazmat/'],  __name__ to cryptography.hazmat for package cryptography.hazmat
[+] Extracted cryptography/hazmat/bindings/__init__.py from archive. The module can be loaded!
[*] Metadata (__package__) set to cryptography.hazmat.bindings : __filepath__ to ['izR72lIk/cryptography/hazmat/bindings/'],  __name__ to cryptography.hazmat.bindings for package cryptography.hazmat.bindings
[PYD] cryptography.hazmat.bindings._rust from C:<something>\tools\losange\examples\izR72lIk/cryptography/hazmat/bindings\_rust.pyd
[PYD] _cffi_backend from C:<something>\tools\losange\examples\izR72lIk\_cffi_backend.cp312-win_amd64.pyd
[EXEC] Executing module: _cffi_backend
[EXEC] Executing module: cryptography.hazmat.bindings._rust
```

We need both because not setting `sys.path` for *pythonnet* results in this error during the import:
```powershell
Traceback (most recent call last):
  File "C:<something>tools\losange\examples\customloader-pythonnet.py", line 351, in <module>
    rt = get_netfx()
         ^^^^^^^^^^^
  File "<string>", line 166, in get_netfx
ImportError: cannot import name 'NetFx' from 'clr_loader.netfx' (SnpzYnnT/clr_loader/netfx.py)
```

And if we don't set our loader at the start of `sys.meta_path` for Impacket, we get this error:

```powershell
Traceback (most recent call last):
  File "C:<something>tools\losange\examples\customloader-secretsdump.py", line 359, in <module>
    from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
ImportError: cannot import name 'LocalOperations' from 'impacket.examples.secretsdump' (9ro9grFl/impacket/examples/secretsdump.py)
```



## External Dependencies

Dependencies are automatically written to disk if their extension is provided in the `add_remote_bytes` function. Contrary to *pyd* files, their relative paths in the ZIP archive are not preserved, and therefore are written to the current working directory. I wasn't able to fake the package on disk that satisfied *cffi*'s way of loading DLLs (LoadLibrary essentially)

A few changes are required in the *pythonnet* and *clr_loader* packages to account for this issue.  

In `pythonnet\__init__.py`:

```python
def load(runtime: Union[clr_loader.Runtime, str, None] = None, **params: str) -> None:
    """Load Python.NET in the specified runtime

    The same parameters as for `set_runtime` can be used. By default,
    `set_default_runtime` is called if no environment has been set yet and no
    parameters are passed.

    After a successful call, further invocations will return immediately."""
    global _LOADED, _LOADER_ASSEMBLY

    [SNIP]

    # original code
    # dll_path = Path(__file__).parent / "runtime" / "Python.Runtime.dll"
    
    # modified code
    dll_path = "Python.Runtime.dll"

    _LOADER_ASSEMBLY = assembly = _RUNTIME.get_assembly(str(dll_path))
    func = assembly.get_function("Python.Runtime.Loader.Initialize")

    [SNIP]
```


In `clr_loader\ffi\__init__.py` :
```python
def load_netfx():
    if sys.platform != "win32":
        raise RuntimeError(".NET Framework is only supported on Windows")

    # original code
    # dirname = Path(__file__).parent / "dlls"
    # if sys.maxsize > 2**32:
    #     arch = "amd64"
    # else:
    #     arch = "x86"

    #path = dirname / arch / "ClrLoader.dll"
    #return ffi.dlopen(str(path))

    # modified code
    return ffi.dlopen("ClrLoader.dll")
```
In this case, I'm not including the *x86* version of this DLL into my packages.zip archive so *ClrLoader.dll* is the amd64 version. 
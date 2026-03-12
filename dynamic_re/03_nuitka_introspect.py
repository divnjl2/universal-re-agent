"""
Nuitka Runtime Introspection Dumper v1.0

This script is injected into a Nuitka-compiled Python process to extract
real module structure, function signatures, class hierarchies, constants,
and all accessible runtime metadata.

Usage methods:
  A) PYTHONSTARTUP=03_nuitka_introspect.py ./kyc_bot_v1.exe
  B) sitecustomize.py (copy this as sitecustomize.py next to the exe)
  C) Direct: python 03_nuitka_introspect.py <pid>  (attaches via ctypes)
  D) Import from within the process: import nuitka_introspect; nuitka_introspect.dump_all()
"""

import sys
import os
import json
import types
import inspect
import importlib
import traceback
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = os.environ.get("DUMP_OUTPUT_DIR", os.path.dirname(os.path.abspath(__file__)))
DUMP_FILE = os.path.join(OUTPUT_DIR, f"nuitka_runtime_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

# Max depth for recursive inspection
MAX_DEPTH = 3
MAX_ITEMS = 500
MAX_STR_LEN = 2000


def safe_repr(obj, max_len=MAX_STR_LEN):
    """Safe repr that won't crash on weird objects."""
    try:
        r = repr(obj)
        if len(r) > max_len:
            return r[:max_len] + "...<truncated>"
        return r
    except Exception:
        return f"<repr failed: {type(obj).__name__}>"


def safe_str(obj, max_len=MAX_STR_LEN):
    try:
        s = str(obj)
        return s[:max_len] if len(s) > max_len else s
    except Exception:
        return f"<str failed>"


def get_signature(func):
    """Extract function signature safely."""
    try:
        sig = inspect.signature(func)
        params = []
        for name, param in sig.parameters.items():
            p = {"name": name, "kind": str(param.kind.name)}
            if param.default is not inspect.Parameter.empty:
                p["default"] = safe_repr(param.default, 200)
            if param.annotation is not inspect.Parameter.empty:
                p["annotation"] = safe_repr(param.annotation, 200)
            params.append(p)

        ret = {}
        if sig.return_annotation is not inspect.Signature.empty:
            ret["return_annotation"] = safe_repr(sig.return_annotation, 200)

        return {"params": params, **ret}
    except (ValueError, TypeError):
        # Nuitka compiled functions may not have inspectable signatures
        # Try fallback methods
        try:
            code = getattr(func, '__code__', None)
            if code:
                return {
                    "params": [{"name": n, "kind": "POSITIONAL_OR_KEYWORD"}
                               for n in code.co_varnames[:code.co_argcount]],
                    "source": "code_object",
                    "co_argcount": code.co_argcount,
                    "co_kwonlyargcount": getattr(code, 'co_kwonlyargcount', 0),
                }
        except Exception:
            pass
        return None


def inspect_function(func, depth=0):
    """Extract all available info from a function object."""
    info = {
        "type": "function",
        "qualname": getattr(func, '__qualname__', None),
        "module": getattr(func, '__module__', None),
        "doc": getattr(func, '__doc__', None),
    }

    # Signature
    sig = get_signature(func)
    if sig:
        info["signature"] = sig

    # Defaults
    defaults = getattr(func, '__defaults__', None)
    if defaults:
        info["defaults"] = [safe_repr(d, 200) for d in defaults]

    kwdefaults = getattr(func, '__kwdefaults__', None)
    if kwdefaults:
        info["kwdefaults"] = {k: safe_repr(v, 200) for k, v in kwdefaults.items()}

    # Annotations
    annotations = getattr(func, '__annotations__', None)
    if annotations:
        info["annotations"] = {k: safe_repr(v, 200) for k, v in annotations.items()}

    # Code object details (if available)
    code = getattr(func, '__code__', None)
    if code:
        info["code"] = {
            "co_filename": code.co_filename,
            "co_name": code.co_name,
            "co_argcount": code.co_argcount,
            "co_kwonlyargcount": getattr(code, 'co_kwonlyargcount', 0),
            "co_varnames": list(code.co_varnames[:50]),
            "co_names": list(code.co_names[:100]),
            "co_consts": [safe_repr(c, 200) for c in code.co_consts[:50]
                          if not isinstance(c, types.CodeType)],
            "co_freevars": list(code.co_freevars),
            "co_cellvars": list(code.co_cellvars),
        }

    # Closure variables
    closure = getattr(func, '__closure__', None)
    if closure:
        info["closure_values"] = []
        for cell in closure:
            try:
                info["closure_values"].append(safe_repr(cell.cell_contents, 200))
            except ValueError:
                info["closure_values"].append("<empty cell>")

    # Decorators (from wrapper attributes)
    for attr in ('__wrapped__', '__func__'):
        inner = getattr(func, attr, None)
        if inner and inner is not func:
            info[f"_{attr}"] = inspect_function(inner, depth + 1) if depth < 2 else safe_repr(inner)

    return info


def inspect_class(cls, depth=0):
    """Extract all available info from a class."""
    info = {
        "type": "class",
        "qualname": getattr(cls, '__qualname__', None),
        "module": getattr(cls, '__module__', None),
        "doc": getattr(cls, '__doc__', None),
        "bases": [safe_repr(b) for b in cls.__bases__],
        "mro": [safe_repr(c) for c in cls.__mro__],
    }

    # Class annotations (type hints for fields)
    annotations = getattr(cls, '__annotations__', {})
    if annotations:
        info["annotations"] = {k: safe_repr(v, 200) for k, v in annotations.items()}

    # Methods and attributes
    methods = {}
    class_attrs = {}
    properties = {}

    for name in sorted(dir(cls)):
        if name.startswith('__') and name.endswith('__') and name not in (
            '__init__', '__new__', '__call__', '__enter__', '__exit__',
            '__aenter__', '__aexit__', '__iter__', '__next__', '__aiter__',
            '__anext__', '__getitem__', '__setitem__', '__len__', '__str__',
            '__repr__', '__eq__', '__hash__', '__lt__', '__gt__',
            '__post_init__', '__init_subclass__',
        ):
            continue

        try:
            # Get from class dict to avoid descriptor protocol
            if name in cls.__dict__:
                obj = cls.__dict__[name]
            else:
                obj = getattr(cls, name)

            if isinstance(obj, (types.FunctionType, types.MethodType)):
                methods[name] = inspect_function(obj, depth + 1) if depth < MAX_DEPTH else {"type": "method"}
            elif isinstance(obj, (staticmethod, classmethod)):
                inner = obj.__func__ if hasattr(obj, '__func__') else obj
                m = inspect_function(inner, depth + 1) if depth < MAX_DEPTH else {"type": "method"}
                m["decorator"] = type(obj).__name__
                methods[name] = m
            elif isinstance(obj, property):
                properties[name] = {
                    "type": "property",
                    "has_getter": obj.fget is not None,
                    "has_setter": obj.fset is not None,
                    "doc": getattr(obj, '__doc__', None),
                }
            elif not callable(obj):
                class_attrs[name] = {
                    "type": type(obj).__name__,
                    "value": safe_repr(obj, 500),
                }
        except Exception:
            pass

    if methods:
        info["methods"] = methods
    if class_attrs:
        info["class_attributes"] = class_attrs
    if properties:
        info["properties"] = properties

    # Slots
    slots = getattr(cls, '__slots__', None)
    if slots:
        info["slots"] = list(slots) if not isinstance(slots, str) else [slots]

    return info


def inspect_module(mod, depth=0):
    """Extract everything from a module."""
    info = {
        "name": getattr(mod, '__name__', '?'),
        "file": getattr(mod, '__file__', None),
        "package": getattr(mod, '__package__', None),
        "doc": getattr(mod, '__doc__', None),
        "compiled": getattr(mod, '__compiled__', None),
        "loader": safe_repr(getattr(mod, '__loader__', None)),
    }

    # Check if Nuitka compiled
    if hasattr(mod, '__compiled__'):
        info["is_nuitka"] = True

    classes = {}
    functions = {}
    constants = {}
    submodules = []

    count = 0
    for name in sorted(dir(mod)):
        if count > MAX_ITEMS:
            info["_truncated"] = True
            break
        count += 1

        if name.startswith('_') and name != '__all__':
            continue

        try:
            obj = getattr(mod, name)
        except Exception:
            continue

        try:
            obj_mod = getattr(obj, '__module__', None)
        except Exception:
            obj_mod = None

        # Only include things defined in this module
        if obj_mod and obj_mod != mod.__name__:
            # Still note it as an import
            if isinstance(obj, type):
                if name not in ('type', 'object'):
                    info.setdefault("imports", {})[name] = {
                        "from_module": obj_mod,
                        "type": "class",
                    }
            continue

        if isinstance(obj, type):
            classes[name] = inspect_class(obj, depth + 1) if depth < MAX_DEPTH else {"type": "class"}
        elif isinstance(obj, (types.FunctionType, types.BuiltinFunctionType)):
            functions[name] = inspect_function(obj, depth + 1) if depth < MAX_DEPTH else {"type": "function"}
        elif isinstance(obj, types.ModuleType):
            submodules.append(name)
        elif not callable(obj):
            # Constants / module-level variables
            constants[name] = {
                "type": type(obj).__name__,
                "value": safe_repr(obj, 500),
            }

    if classes:
        info["classes"] = classes
    if functions:
        info["functions"] = functions
    if constants:
        info["constants"] = constants
    if submodules:
        info["submodules"] = submodules

    # __all__ export list
    all_list = getattr(mod, '__all__', None)
    if all_list:
        info["__all__"] = list(all_list)

    return info


def dump_all(output_file=None):
    """Main dump function — call after modules are loaded."""
    if output_file is None:
        output_file = DUMP_FILE

    print(f"\n{'='*60}")
    print(f"  NUITKA RUNTIME INTROSPECTION DUMP")
    print(f"  Output: {output_file}")
    print(f"{'='*60}\n")

    result = {
        "timestamp": datetime.now().isoformat(),
        "python_version": sys.version,
        "executable": sys.executable,
        "platform": sys.platform,
        "argv": sys.argv,
        "path": sys.path[:20],
    }

    # Categorize modules
    all_modules = dict(sys.modules)
    stdlib_prefixes = {
        'os', 'sys', 'io', 'abc', 're', 'ast', 'dis', 'ssl', 'csv',
        'json', 'http', 'html', 'xml', 'email', 'urllib', 'logging',
        'collections', 'functools', 'itertools', 'concurrent', 'asyncio',
        'pathlib', 'typing', 'dataclasses', 'enum', 'copy', 'math',
        'hashlib', 'hmac', 'base64', 'binascii', 'struct', 'codecs',
        'importlib', 'pkgutil', 'inspect', 'traceback', 'warnings',
        'contextlib', 'socket', 'select', 'signal', 'threading',
        'multiprocessing', 'subprocess', 'shutil', 'tempfile', 'glob',
        'fnmatch', 'stat', 'posixpath', 'ntpath', 'genericpath',
        'string', 'textwrap', 'unicodedata', 'locale', 'gettext',
        'argparse', 'configparser', 'pprint', 'datetime', 'time',
        'calendar', 'random', 'secrets', 'decimal', 'fractions',
        'numbers', 'operator', 'weakref', 'gc', 'ctypes', 'array',
        'queue', 'heapq', 'bisect', 'pickle', 'shelve', 'sqlite3',
        'zipfile', 'tarfile', 'gzip', 'bz2', 'lzma', 'zlib',
        '_', 'builtins', 'encodings', 'codecs', 'token', 'tokenize',
        'sre_', 'copyreg', 'types', 'keyword', 'linecache', 'atexit',
    }

    third_party_prefixes = {
        'aiogram', 'aiohttp', 'sqlalchemy', 'alembic', 'redis',
        'celery', 'fastapi', 'uvicorn', 'starlette', 'pydantic',
        'httpx', 'aiofiles', 'apscheduler', 'cryptography', 'jwt',
        'PIL', 'numpy', 'requests', 'urllib3', 'certifi', 'charset',
        'idna', 'multidict', 'yarl', 'aiosignal', 'frozenlist',
        'attr', 'attrs', 'click', 'jinja2', 'markupsafe', 'werkzeug',
        'flask', 'django', 'celery', 'kombu', 'vine', 'amqp',
        'ccxt', 'web3', 'eth_utils', 'eth_abi', 'eth_account',
        'solders', 'solana', 'anchorpy', 'borsh',
        'frida', 'psutil', 'pip', 'setuptools', 'pkg_resources',
        'pytz', 'dateutil', 'six', 'wrapt', 'decorator',
        'google', 'grpc', 'protobuf', 'boto', 'botocore',
    }

    custom_modules = {}
    thirdparty_modules = {}
    module_names = {"stdlib": [], "thirdparty": [], "custom": [], "nuitka_internal": []}

    for name, mod in sorted(all_modules.items()):
        if mod is None:
            continue

        top = name.split('.')[0]

        # Nuitka internal modules
        if top.startswith('__nuitka') or top == '__parents_main__':
            module_names["nuitka_internal"].append(name)
            continue

        # Stdlib
        if top in stdlib_prefixes or name.startswith(('_frozen', '_io', '_thread', '_signal')):
            module_names["stdlib"].append(name)
            continue

        # Third party
        is_thirdparty = False
        for prefix in third_party_prefixes:
            if top == prefix or top.startswith(prefix + '.'):
                is_thirdparty = True
                break

        if is_thirdparty:
            module_names["thirdparty"].append(name)
            try:
                thirdparty_modules[name] = {
                    "file": getattr(mod, '__file__', None),
                    "version": getattr(mod, '__version__', None),
                }
            except Exception:
                pass
            continue

        # Custom / project module
        module_names["custom"].append(name)
        try:
            print(f"  Inspecting: {name}")
            custom_modules[name] = inspect_module(mod)
        except Exception as e:
            custom_modules[name] = {"error": str(e)}

    result["module_counts"] = {k: len(v) for k, v in module_names.items()}
    result["module_names"] = module_names
    result["thirdparty_info"] = thirdparty_modules
    result["custom_modules"] = custom_modules

    # Dump global string constants from builtins/globals
    print(f"\n  Modules inspected: {len(custom_modules)} custom, "
          f"{len(module_names['thirdparty'])} thirdparty, "
          f"{len(module_names['stdlib'])} stdlib")

    # Save
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)

    size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"\n  Dump saved: {output_file} ({size_mb:.1f} MB)")
    print(f"{'='*60}\n")

    return output_file


def dump_after_delay(delay_seconds=5):
    """Schedule dump after a delay (gives time for imports to complete)."""
    import threading

    def _do_dump():
        import time
        time.sleep(delay_seconds)
        dump_all()

    t = threading.Thread(target=_do_dump, daemon=True)
    t.start()
    print(f"[introspect] Dump scheduled in {delay_seconds}s...")


# =====================================================================
# Auto-execution modes
# =====================================================================

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        # Mode C: Attach to running process by PID
        print("PID attach mode not implemented yet — use PYTHONSTARTUP method")
        sys.exit(1)
    else:
        # Direct run — dump current interpreter state
        dump_all()

elif os.environ.get("NUITKA_DUMP_ON_START") == "1":
    # Mode A: via PYTHONSTARTUP or sitecustomize
    # Delay to allow all modules to load
    dump_after_delay(delay_seconds=int(os.environ.get("NUITKA_DUMP_DELAY", "10")))

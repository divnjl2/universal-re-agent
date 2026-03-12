"""
sitecustomize.py — Drop-in hook for Nuitka binaries.

Place this file NEXT TO the Nuitka .exe file.
When the exe starts, Python will auto-import this before main code.

It hooks sys.modules to capture all imports, then dumps everything
after a delay.
"""

import sys
import os
import threading
import time
import json
import atexit
from datetime import datetime

# Config
DUMP_DELAY = int(os.environ.get("NUITKA_DUMP_DELAY", "15"))
DUMP_DIR = os.environ.get("DUMP_OUTPUT_DIR", os.path.dirname(os.path.abspath(__file__)))

# Track import order
_import_order = []
_original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__
_start_time = time.time()


def _hooked_import(name, *args, **kwargs):
    """Track every import with timestamp."""
    result = _original_import(name, *args, **kwargs)
    _import_order.append({
        "name": name,
        "time": time.time() - _start_time,
    })
    return result


# Install import hook
try:
    __builtins__.__import__ = _hooked_import
except (AttributeError, TypeError):
    pass  # Some Python builds don't allow this


def _do_dump():
    """Delayed dump of all runtime state."""
    time.sleep(DUMP_DELAY)

    # Import the introspection module
    dump_dir = os.path.dirname(os.path.abspath(__file__))
    introspect_path = os.path.join(dump_dir, "03_nuitka_introspect.py")

    if os.path.exists(introspect_path):
        # Use the full introspection module
        import importlib.util
        spec = importlib.util.spec_from_file_location("nuitka_introspect", introspect_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        output_file = mod.dump_all()

        # Append import order to the dump
        if output_file and os.path.exists(output_file):
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            data["import_order"] = _import_order
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    else:
        # Minimal dump if introspect script not found
        output_file = os.path.join(DUMP_DIR, f"minimal_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        modules = {}
        for name, mod in sorted(sys.modules.items()):
            if mod is None:
                continue
            modules[name] = {
                "file": getattr(mod, '__file__', None),
                "package": getattr(mod, '__package__', None),
                "compiled": getattr(mod, '__compiled__', None),
                "attrs": [a for a in dir(mod) if not a.startswith('_')][:100],
            }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "python_version": sys.version,
                "executable": sys.executable,
                "modules": modules,
                "import_order": _import_order,
            }, f, indent=2, ensure_ascii=False, default=str)

    print(f"[sitecustomize] Dump complete: {output_file}")


# Schedule the dump
_dump_thread = threading.Thread(target=_do_dump, daemon=True)
_dump_thread.start()

# Also dump on exit as backup
def _exit_dump():
    try:
        output_file = os.path.join(DUMP_DIR, f"exit_modules_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        modules = {}
        for name, mod in sorted(sys.modules.items()):
            if mod is None:
                continue
            modules[name] = {
                "file": getattr(mod, '__file__', None),
                "attrs": [a for a in dir(mod) if not a.startswith('_')][:50],
            }
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"modules": modules, "import_order": _import_order},
                      f, indent=2, ensure_ascii=False, default=str)
    except Exception:
        pass

atexit.register(_exit_dump)
print(f"[sitecustomize] Hooks installed. Dump in {DUMP_DELAY}s...")

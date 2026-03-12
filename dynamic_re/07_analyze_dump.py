"""
Analyze runtime dumps and generate real Python source code.

Takes the output from 03_nuitka_introspect.py and 04_memory_dump.py,
combines them, and generates source code with REAL signatures,
constants, class hierarchies, and string data.

Usage:
  python 07_analyze_dump.py runtime_dump.json [memory_dump.json] [--output-dir recovered/]
"""

import sys
import os
import json
import re
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def load_dumps(runtime_path, memory_path=None):
    """Load and merge dump files."""
    with open(runtime_path, 'r', encoding='utf-8') as f:
        runtime = json.load(f)

    memory = None
    if memory_path and os.path.exists(memory_path):
        with open(memory_path, 'r', encoding='utf-8') as f:
            memory = json.load(f)

    return runtime, memory


def generate_function_code(name, info, indent=""):
    """Generate function definition from introspection data."""
    lines = []

    # Decorator
    decorator = info.get("decorator")
    if decorator:
        lines.append(f"{indent}@{decorator}")

    # Build signature
    params = []
    sig = info.get("signature", {})
    sig_params = sig.get("params", [])

    defaults = info.get("defaults", [])
    kwdefaults = info.get("kwdefaults", {})
    annotations = info.get("annotations", {})

    for i, p in enumerate(sig_params):
        pname = p["name"]
        kind = p.get("kind", "POSITIONAL_OR_KEYWORD")

        # Annotation
        ann = p.get("annotation") or annotations.get(pname)
        ann_str = f": {_clean_annotation(ann)}" if ann else ""

        # Default value
        default = p.get("default")
        default_str = f" = {_clean_default(default)}" if default else ""

        if kind == "VAR_POSITIONAL":
            params.append(f"*{pname}{ann_str}")
        elif kind == "VAR_KEYWORD":
            params.append(f"**{pname}{ann_str}")
        elif kind == "KEYWORD_ONLY":
            # Insert * separator if not already
            if not any(pp.startswith('*') and not pp.startswith('**') for pp in params):
                params.append("*")
            kw_default = kwdefaults.get(pname)
            if kw_default:
                params.append(f"{pname}{ann_str} = {_clean_default(kw_default)}")
            else:
                params.append(f"{pname}{ann_str}{default_str}")
        else:
            params.append(f"{pname}{ann_str}{default_str}")

    # Fallback to code object
    if not sig_params and "code" in info:
        code = info["code"]
        varnames = code.get("co_varnames", [])
        argcount = code.get("co_argcount", 0)
        for vn in varnames[:argcount]:
            params.append(vn)

    # Return annotation
    ret_ann = sig.get("return_annotation") or annotations.get("return")
    ret_str = f" -> {_clean_annotation(ret_ann)}" if ret_ann else ""

    # Async detection
    async_prefix = "async " if name.startswith(("async_", "a")) and any(
        kw in name for kw in ("fetch", "get", "post", "send", "create", "delete", "update", "handle", "process")
    ) else ""

    # Check code object for coroutine flag
    if info.get("code", {}).get("co_flags", 0) & 0x100:  # CO_COROUTINE
        async_prefix = "async "

    param_str = ", ".join(params)
    lines.append(f"{indent}{async_prefix}def {name}({param_str}){ret_str}:")

    # Docstring
    doc = info.get("doc")
    if doc and doc.strip():
        doc_clean = doc.strip().replace('"""', "'''")
        if '\n' in doc_clean:
            lines.append(f'{indent}    """{doc_clean}"""')
        else:
            lines.append(f'{indent}    """{doc_clean}"""')

    # Body from code object constants and names
    code = info.get("code", {})
    co_names = code.get("co_names", [])
    co_consts = code.get("co_consts", [])

    body_hints = []
    if co_names:
        body_hints.append(f"{indent}    # References: {', '.join(co_names[:20])}")
    if co_consts:
        meaningful_consts = [c for c in co_consts if c not in ('None', 'True', 'False', '0', '1', "''", '""')]
        if meaningful_consts:
            body_hints.append(f"{indent}    # Constants: {', '.join(str(c)[:60] for c in meaningful_consts[:10])}")

    if body_hints:
        lines.extend(body_hints)

    lines.append(f"{indent}    ...")
    lines.append("")

    return "\n".join(lines)


def _clean_annotation(ann):
    """Clean up annotation repr for source code."""
    if not ann:
        return ""
    ann = str(ann)
    # Remove <class '...'> wrapper
    ann = re.sub(r"<class '([^']+)'>", r"\1", ann)
    # Remove module prefixes for common types
    for prefix in ('builtins.', 'typing.'):
        ann = ann.replace(prefix, '')
    return ann


def _clean_default(default):
    """Clean up default value repr."""
    if not default:
        return ""
    d = str(default)
    if d == 'None':
        return 'None'
    if d in ('True', 'False'):
        return d
    return d


def generate_class_code(name, info, indent=""):
    """Generate class definition from introspection data."""
    lines = []

    # Bases
    bases = info.get("bases", [])
    base_names = []
    for b in bases:
        b = re.sub(r"<class '([^']+)'>", r"\1", str(b))
        if b != 'object':
            # Simplify module paths
            parts = b.rsplit('.', 1)
            base_names.append(parts[-1] if len(parts) > 1 else b)

    base_str = f"({', '.join(base_names)})" if base_names else ""
    lines.append(f"{indent}class {name}{base_str}:")

    # Docstring
    doc = info.get("doc")
    if doc and doc.strip():
        lines.append(f'{indent}    """{doc.strip()}"""')

    has_content = False

    # Annotations (type hints)
    annotations = info.get("annotations", {})
    if annotations:
        lines.append(f"{indent}    # Type annotations")
        for attr_name, attr_type in annotations.items():
            type_str = _clean_annotation(attr_type)
            lines.append(f"{indent}    {attr_name}: {type_str}")
        lines.append("")
        has_content = True

    # Slots
    slots = info.get("slots", [])
    if slots:
        lines.append(f"{indent}    __slots__ = {slots!r}")
        lines.append("")
        has_content = True

    # Class attributes
    class_attrs = info.get("class_attributes", {})
    if class_attrs:
        for attr_name, attr_info in class_attrs.items():
            val = attr_info.get("value", "None")
            lines.append(f"{indent}    {attr_name} = {val}")
        lines.append("")
        has_content = True

    # Properties
    properties = info.get("properties", {})
    for prop_name, prop_info in properties.items():
        lines.append(f"{indent}    @property")
        doc = prop_info.get("doc")
        if doc:
            lines.append(f"{indent}    def {prop_name}(self):")
            lines.append(f'{indent}        """{doc}"""')
        else:
            lines.append(f"{indent}    def {prop_name}(self):")
        lines.append(f"{indent}        ...")
        lines.append("")
        if prop_info.get("has_setter"):
            lines.append(f"{indent}    @{prop_name}.setter")
            lines.append(f"{indent}    def {prop_name}(self, value):")
            lines.append(f"{indent}        ...")
            lines.append("")
        has_content = True

    # Methods
    methods = info.get("methods", {})
    for method_name, method_info in methods.items():
        if isinstance(method_info, dict) and method_info.get("type") in ("function", "method", None):
            lines.append(generate_function_code(method_name, method_info, indent=indent + "    "))
            has_content = True

    if not has_content:
        lines.append(f"{indent}    ...")
        lines.append("")

    return "\n".join(lines)


def generate_module_file(mod_name, mod_info, all_strings=None):
    """Generate a complete Python source file from module introspection."""
    lines = []

    # Module docstring
    doc = mod_info.get("doc")
    if doc:
        lines.append(f'"""{doc}"""')
    else:
        lines.append(f'"""Module: {mod_name}"""')

    # Determine imports from referenced modules
    imports = mod_info.get("imports", {})
    if imports:
        lines.append("")
        # Group imports by source module
        import_groups = defaultdict(list)
        for imp_name, imp_info in imports.items():
            from_mod = imp_info.get("from_module", "")
            import_groups[from_mod].append(imp_name)

        for from_mod, names in sorted(import_groups.items()):
            if len(names) > 3:
                names_str = ",\n    ".join(sorted(names))
                lines.append(f"from {from_mod} import (\n    {names_str},\n)")
            else:
                lines.append(f"from {from_mod} import {', '.join(sorted(names))}")

    # Module-level constants
    constants = mod_info.get("constants", {})
    if constants:
        lines.append("")
        lines.append("# Module constants")
        for const_name, const_info in sorted(constants.items()):
            val = const_info.get("value", "None")
            lines.append(f"{const_name} = {val}")

    # Classes
    classes = mod_info.get("classes", {})
    if classes:
        for cls_name, cls_info in sorted(classes.items()):
            lines.append("")
            lines.append("")
            lines.append(generate_class_code(cls_name, cls_info))

    # Module-level functions
    functions = mod_info.get("functions", {})
    if functions:
        for func_name, func_info in sorted(functions.items()):
            lines.append("")
            lines.append("")
            lines.append(generate_function_code(func_name, func_info))

    # If module has __all__, add it
    all_list = mod_info.get("__all__")
    if all_list:
        lines.insert(2, f"\n__all__ = {all_list!r}\n")

    return "\n".join(lines)


def write_recovered_source(runtime_data, memory_data, output_dir):
    """Generate all recovered source files."""
    custom_modules = runtime_data.get("custom_modules", {})

    if not custom_modules:
        print("ERROR: No custom modules found in dump!")
        return

    # Collect all strings from memory dump for enrichment
    all_strings = set()
    if memory_data:
        for s in memory_data.get("strings", {}).get("ascii", []):
            all_strings.add(s)
        for s in memory_data.get("strings", {}).get("unicode", []):
            all_strings.add(s)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    generated = []
    for mod_name, mod_info in sorted(custom_modules.items()):
        if isinstance(mod_info, dict) and "error" not in mod_info:
            # Convert module name to file path
            parts = mod_name.split('.')
            if mod_info.get("submodules"):
                # Package — create __init__.py
                file_path = output_path / Path(*parts) / "__init__.py"
            else:
                file_path = output_path / Path(*parts[:-1]) / f"{parts[-1]}.py" if len(parts) > 1 else output_path / f"{parts[0]}.py"

            file_path.parent.mkdir(parents=True, exist_ok=True)

            source = generate_module_file(mod_name, mod_info, all_strings)

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(source)

            generated.append({
                "module": mod_name,
                "file": str(file_path),
                "classes": len(mod_info.get("classes", {})),
                "functions": len(mod_info.get("functions", {})),
                "constants": len(mod_info.get("constants", {})),
            })

    # Write manifest
    manifest_path = output_path / "MANIFEST.json"
    manifest = {
        "generated_at": datetime.now().isoformat(),
        "source": "dynamic_runtime_introspection",
        "python_version": runtime_data.get("python_version", "?"),
        "total_modules": len(generated),
        "total_classes": sum(g["classes"] for g in generated),
        "total_functions": sum(g["functions"] for g in generated),
        "module_counts": runtime_data.get("module_counts", {}),
        "files": generated,
    }

    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"\n  Generated {len(generated)} source files in {output_dir}")
    print(f"  Total: {manifest['total_classes']} classes, {manifest['total_functions']} functions")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Analyze Nuitka runtime dumps")
    parser.add_argument("runtime_dump", help="Path to runtime introspection dump JSON")
    parser.add_argument("memory_dump", nargs="?", help="Path to memory dump JSON (optional)")
    parser.add_argument("--output-dir", "-o", default="recovered_dynamic",
                        help="Output directory for generated source")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  NUITKA DUMP ANALYZER")
    print(f"{'='*60}\n")

    runtime, memory = load_dumps(args.runtime_dump, args.memory_dump)

    print(f"  Runtime dump: {args.runtime_dump}")
    print(f"  Modules: {runtime.get('module_counts', {})}")

    if memory:
        print(f"  Memory dump: {args.memory_dump}")
        print(f"  Strings: {memory.get('strings', {}).get('ascii_count', 0)} ASCII, "
              f"{memory.get('strings', {}).get('unicode_count', 0)} Unicode")

    manifest = write_recovered_source(runtime, memory, args.output_dir)

    print(f"\n{'='*60}")
    print(f"  DONE")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    main()

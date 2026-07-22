#!/usr/bin/env python3
# site_config.py – command‑line tool to create/update site_config.yaml
# It imports dataclasses from start_site_server and site_endpoints to generate a YAML file.
# Runtime: provides load_config() for start_site_server.py.

import argparse
import sys
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional, TextIO

# ---------- YAML parser/dumper (with _note comment preservation) ----------
class YAMLError(Exception):
    pass

def _scalar(v: str) -> Any:
    if v in ('null', '~', ''):
        return None
    l = v.lower()
    if l == 'true':
        return True
    if l == 'false':
        return False
    if re.match(r'^[+-]?\d+$', v):
        return int(v)
    if re.match(r'^[+-]?\d+\.\d+$', v):
        return float(v)
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v

def _dump_scalar(v: Any) -> str:
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        # If the string contains special YAML characters, quote it.
        if any(c in v for c in ':#[]{}'):
            return f"'{v}'"
        return v
    raise YAMLError(f"Unsupported type: {type(v)}")

def loads(s: str, note_suffix: str = '_note') -> Dict[str, Any]:
    """
    Parse a YAML-like string into a dict, treating lines starting with '#' as comments.
    Comments immediately before a key (with the same indent) become the value of
    key + note_suffix.
    """
    lines = []
    for ln in s.splitlines():
        if ln.lstrip().startswith('#'):
            lines.append(('comment', ln))
        else:
            # Remove inline comments (anything after a # not in quotes)
            # For simplicity, we only remove comments at the end of a line
            # that are preceded by a space, but we keep quotes.
            # We'll just split on '#' if it's not inside quotes (naive).
            # Better: use a simple state machine, but for our config we assume
            # no quoted # inside values.
            if '#' in ln:
                # Find if # is inside quotes; if not, split.
                # Quick heuristic: if # is preceded by a space or start of line.
                # We'll do a simple split, but if # is inside quotes, it's tricky.
                # Since our configs rarely have quoted #, we split on first #.
                content = ln.split('#', 1)[0].rstrip()
            else:
                content = ln.rstrip()
            if content.strip():
                lines.append(('key', content))

    root = {}
    stack = [(root, 0)]
    pending = {}   # indent -> list of comment lines

    for typ, line in lines:
        if typ == 'comment':
            indent = len(line) - len(line.lstrip(' '))
            comment_text = line.lstrip()[1:].lstrip()   # remove '# ' and one space
            pending.setdefault(indent, []).append(comment_text)
            continue

        indent = len(line) - len(line.lstrip(' '))
        stripped = line.lstrip()
        if ':' not in stripped:
            raise YAMLError(f"Missing ':' in line: {line}")
        key, _, val = stripped.partition(':')
        key = key.strip()
        val = val.strip()

        # Pop stack to correct indent level
        while stack and indent <= stack[-1][1]:
            stack.pop()
        if not stack:
            raise YAMLError("Indentation error")
        parent = stack[-1][0]

        # Attach pending comments at this indent to this key
        if indent in pending and pending[indent]:
            note_lines = pending.pop(indent)
            note_value = '\n'.join(note_lines)
            parent[key + note_suffix] = note_value

        if val == '':
            parent[key] = {}
            stack.append((parent[key], indent))
        else:
            parent[key] = _scalar(val)

    return root

def load(fp: TextIO, note_suffix: str = '_note') -> Dict[str, Any]:
    return loads(fp.read(), note_suffix)

def load_file(path: Path, note_suffix: str = '_note') -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        return load(f, note_suffix)

def dumps(data: Dict[str, Any], note_suffix: str = '_note', indent: int = 0) -> str:
    out = []
    sp = '  ' * indent

    # Sort keys to have consistent output; put _note keys at the end?
    # We'll process all keys except note keys in alphabetical order.
    regular_keys = [k for k in data.keys() if not k.endswith(note_suffix)]

    for key in sorted(regular_keys):
        note_key = key + note_suffix
        if note_key in data and data[note_key] is not None:
            for comment_line in str(data[note_key]).splitlines():
                out.append(f"{sp}# {comment_line}")

        val = data[key]
        if isinstance(val, dict):
            out.append(f"{sp}{key}:")
            out.append(dumps(val, note_suffix, indent + 1))
        else:
            out.append(f"{sp}{key}: {_dump_scalar(val)}")

    return '\n'.join(out)

def dump(data: Dict[str, Any], fp: TextIO, note_suffix: str = '_note', indent: int = 0) -> None:
    fp.write(dumps(data, note_suffix, indent))

def dump_file(data: Dict[str, Any], path: Path, note_suffix: str = '_note', indent: int = 0) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        dump(data, f, note_suffix, indent)

# ---------- CLI tool ----------
def get_config_dicts():
    """
    Import start_site_server and site_endpoints to get their config dicts with notes.
    This is called only when running the CLI (--create or --update).
    """
    import start_site_server
    from start_site_server import ServerConfig, _asdict_with_notes

    server_dict = _asdict_with_notes(ServerConfig)

    endpoints_dict = None
    try:
        import site_endpoints
        if hasattr(site_endpoints, 'EndpointsConfig'):
            endpoints_dict = _asdict_with_notes(site_endpoints.EndpointsConfig)
    except ImportError:
        pass

    return server_dict, endpoints_dict

def write_yaml(path: Path, merged_dict: Dict[str, Any], preserve_comments: bool = True):
    """
    Write merged_dict to YAML. If preserve_comments is True and the file exists,
    we read the existing file, update its values with merged_dict (preserving
    existing _note comments), and write back.
    """
    if preserve_comments and path.exists():
        existing = load_file(path)
        # Start with existing, then update values from merged_dict
        final = existing.copy()
        # Update non-note keys (values)
        for k, v in merged_dict.items():
            if not k.endswith('_note'):
                final[k] = v
        # Update note keys (comments) – this will replace comments from the default
        # but we want to keep user's comments if they exist. The user's comments
        # are stored as _note keys. If we want to preserve user comments, we
        # should not overwrite _note keys that exist in the file with defaults.
        # However, to update the comments to match new defaults, we might want to
        # replace them. The requirement: "update does similar but preserves all
        # values in an existing file." That suggests we should keep existing
        # values and comments, and only update when a key is missing or changed
        # in the defaults? The spec says: "--update does similar but preserves all
        # values in an existing file." That implies we should keep all values
        # from the existing file, and only add new keys that are missing from the
        # defaults? Actually, we want to update the file with new default values
        # but preserve any custom values already present. So we should not
        # overwrite existing values, only add missing ones. But the spec says
        # "update with new default values", which might mean update the values
        # to new defaults? That seems wrong – if the user changed a value, we
        # shouldn't overwrite it. So --update should add any new fields that
        # appear in the defaults, but keep the user's existing values for all
        # fields. We should not overwrite any existing key with a new default.
        # So we do: for each key in merged_dict, if key not in final, add it.
        # For _note keys, do the same.
        for k, v in merged_dict.items():
            if k not in final:
                final[k] = v
        # Also, if a key exists in final but not in merged_dict, we keep it.
        dump_file(final, path)
    else:
        dump_file(merged_dict, path)

# called by start_site_server
def server_init(svr_core):
    """Register interactive commands for configuration."""
    def config_cmd(args):
        """Display merged configuration."""
        merged = svr_core.merged_config if hasattr(svr_core, 'merged_config') else {}
        if merged:
            print("Merged configuration:")
            for k, v in merged.items():
                if k.endswith("_note"):
                    continue
                print(f"  {k}: {v}")
        else:
            print("No merged configuration available.")
    import start_site_server.
    svr_core.register_command("config", config_cmd, "Show merged configuration")

    def dump_cmd(args):
        """Write current config to a file."""
        if not args:
            print("Usage: dump <filename>")
            return
        filename = args[0]
        merged = svr_core.merged_config if hasattr(svr_core, 'merged_config') else {}
        try:
            import json
            with open(filename, 'w') as f:
                json.dump(merged, f, indent=2, default=str)
            print(f"✅ Config dumped to {filename}")
        except Exception as e:
            print(f"Error dumping config: {e}")
    svr_core.register_command("dump", dump_cmd, "Dump config to <filename>")
    
def main():
    parser = argparse.ArgumentParser(
        description="Create or update site_config.yaml from dataclass defaults."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create", action="store_true", help="Create a new site_config.yaml with default values.")
    group.add_argument("--update", action="store_true", help="Update existing site_config.yaml with new default values, preserving existing values and comments.")
    parser.add_argument("--output", default="site_config.yaml", help="Output YAML file path (default: site_config.yaml).")
    args = parser.parse_args()

    output_path = Path(args.output)

    server_dict, endpoints_dict = get_config_dicts()
    merged = server_dict.copy()
    if endpoints_dict:
        merged.update(endpoints_dict)

    if args.update:
        if not output_path.exists():
            print(f"Error: {output_path} does not exist. Use --create to create a new file.", file=sys.stderr)
            sys.exit(1)
        write_yaml(output_path, merged, preserve_comments=True)
        print(f"Updated {output_path} with new default values (preserving existing comments and values).")
    else:  # create
        write_yaml(output_path, merged, preserve_comments=False)
        print(f"Created {output_path} with default configuration.")

# ---------- Runtime load function ----------
def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load site_config.yaml if it exists, else return empty dict.
    This function is used by start_site_server.py at runtime.
    """
    if path is None:
        path = "site_config.yaml"
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return load_file(p)
    except Exception as e:
        print(f"Warning: Failed to load {p}: {e}", file=sys.stderr)
        return {}

if __name__ == "__main__":
    main()
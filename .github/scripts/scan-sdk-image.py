import base64
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
import urllib.parse

REDUCER_SOURCE = '"""Passive stdlib SDK scan reducer and private same-code DATA controls.\n\nNo file/process/network/product/package execution. The workflow owner supplies\ncomplete observed buffers only after owned cleanup; no raw input is returned.\n"""\nimport base64\nimport copy\nimport datetime\nimport hashlib\nimport json\nimport math\nimport re\nimport tomllib\n\nSR_SCOPE = \'C04_SDK_IMAGE_SCAN\'\nSR_RAW_MAX = 67108864\nSR_VERSION_MAX = 1048576\nSR_SUMMARY_MAX = 1048576\nSR_WITNESS_MAX = 16777216\nSR_MEMBER_MAX = 1048576\nSR_ERRORS = (\'BOOTSTRAP\',\'SOURCE\',\'TOOL\',\'BUILD\',\'LINEAGE\',\'ARCHIVE\',\'WITNESS\',\n             \'SCANNER\',\'DB\',\'JSON\',\'OS\',\'PYTHON\',\'RUST\',\'NODE\',\'EXIT\',\'OVERFLOW\',\n             \'CLEANUP\',\'CANCELLED\',\'INTERNAL\')\nSR_LIMITS = [\n    \'Python interpreter, standard library and arbitrary vendored code are not proven by installed-distribution inventory.\',\n    \'Rust build-only dependencies are outside cargo-auditable runtime inventory.\',\n    \'OS support is the selected Trivy scanner table at scan time, not current vendor support or universal advisory completeness.\'\n]\nSR_VENV = \'/app/integrations/sycope/.venv\'\nSR_LOCK = \'integrations/sycope/uv.lock\'\nSR_PROJECT = \'integrations/sycope/pyproject.toml\'\nSR_REQUIRED_SOURCE = {\'.dockerignore\',\'integrations/sycope/Dockerfile\',\n                      \'integrations/sycope/.python-version\',SR_LOCK,SR_PROJECT}\nSR_HELP_FLAGS = {\'--input\',\'--scanners\',\'--pkg-types\',\'--list-all-pkgs\',\n                 \'--format\',\'--severity\',\'--exit-code\',\'--cache-dir\',\'--config\',\'--ignorefile\'}\n# Exact requested Trivy v0.57.1 Debian table for the SDK\'s modern Debian profile.\nSR_DEBIAN_EOL = {\'7\':\'2018-05-31T23:59:59Z\',\'8\':\'2020-06-30T23:59:59Z\',\n                 \'9\':\'2022-06-30T23:59:59Z\',\'10\':\'2024-06-30T23:59:59Z\',\n                 \'11\':\'2026-08-14T23:59:59Z\',\'12\':\'2028-06-10T23:59:59Z\',\n                 \'13\':\'3000-01-01T23:59:59Z\'}\nSR_ID_KEYS = (\'source_head\',\'source_sha256\',\'image_id\',\'archive_sha256\',\n              \'scanner_image_id\',\'report_sha256\',\'version_sha256\',\'witness_sha256\',\n              \'build_metadata_sha256\',\'uv_material_digest\',\'uv_platform_manifest_digest\')\n\n\nclass SRRejected(Exception):\n    def __init__(self, code):\n        self.code = code if code in SR_ERRORS else \'INTERNAL\'\n\n\ndef sr_need(value, code):\n    if not value:\n        raise SRRejected(code)\n\n\ndef sr_closed(value, keys, code):\n    sr_need(type(value) is dict and set(value) == set(keys), code)\n\n\ndef sr_int(value, low, high, code):\n    sr_need(type(value) is int and low <= value <= high, code)\n    return value\n\n\ndef sr_hash(value, code):\n    sr_need(type(value) is str and re.fullmatch(\'[0-9a-f]{64}\', value) is not None, code)\n    return value\n\n\ndef sr_image(value, code):\n    sr_need(type(value) is str and re.fullmatch(\'sha256:[0-9a-f]{64}\', value) is not None, code)\n    return value\n\n\ndef sr_digest(raw):\n    return hashlib.sha256(raw).hexdigest()\n\n\ndef sr_canonical(value):\n    return json.dumps(value,sort_keys=True,separators=(\',\',\':\'),ensure_ascii=True,allow_nan=False).encode(\'ascii\')\n\n\ndef sr_text(value, limit, code, empty=False):\n    sr_need(type(value) is str and (empty or bool(value)) and len(value) <= limit and\n            \'\\0\' not in value and not any(0xD800 <= ord(c) <= 0xDFFF for c in value), code)\n    return value\n\n\ndef sr_walk(value, code=\'JSON\'):\n    count = [0]\n    def walk(item, depth=0):\n        count[0] += 1\n        sr_need(depth <= 32 and count[0] <= 2000000, code)\n        if type(item) is dict:\n            sr_need(len(item) <= 200000, code)\n            for key, child in item.items():\n                sr_text(key,65536,code,True); walk(child,depth+1)\n        elif type(item) is list:\n            sr_need(len(item) <= 200000, code)\n            for child in item: walk(child,depth+1)\n        elif type(item) is str:\n            sr_text(item,SR_RAW_MAX,code,True)\n        elif type(item) is int:\n            sr_need(abs(item) <= 2**63-1, code)\n        elif type(item) is float:\n            sr_need(math.isfinite(item) and abs(item) <= 2**63-1, code)\n        else:\n            sr_need(item is None or type(item) is bool, code)\n    walk(value)\n\n\ndef sr_json(raw, cap):\n    sr_need(type(raw) is bytes and 0 < len(raw) <= cap, \'JSON\')\n    try:\n        text = raw.decode(\'utf-8\',\'strict\')\n        # Bound depth before decoding; braces inside strings do not count.\n        depth = 0; quoted = False; escaped = False\n        for char in text:\n            if quoted:\n                if escaped: escaped = False\n                elif char == \'\\\\\': escaped = True\n                elif char == \'"\': quoted = False\n            elif char == \'"\': quoted = True\n            elif char in \'[{\':\n                depth += 1; sr_need(depth <= 32,\'JSON\')\n            elif char in \']}\': depth -= 1\n        def pairs(rows):\n            result = {}\n            for key, value in rows:\n                sr_need(key not in result,\'JSON\'); result[key] = value\n            return result\n        def constant(_value):\n            raise SRRejected(\'JSON\')\n        value = json.loads(text,object_pairs_hook=pairs,parse_constant=constant)\n        sr_walk(value)\n        return value\n    except (UnicodeError,ValueError,RecursionError,OverflowError):\n        raise SRRejected(\'JSON\') from None\n\n\ndef sr_b64(value, cap, code):\n    sr_text(value,4*((cap+2)//3)+4,code)\n    try: raw = base64.b64decode(value,validate=True)\n    except (ValueError,UnicodeError): raise SRRejected(code) from None\n    sr_need(0 < len(raw) <= cap,code)\n    return raw\n\n\ndef sr_path(value, code, absolute=True):\n    sr_text(value,4096,code)\n    sr_need(not any(ord(c) < 32 or ord(c) == 127 for c in value) and\n            value.startswith(\'/\') is absolute and not value.endswith(\'/\'),code)\n    parts = value.split(\'/\')[1:] if absolute else value.split(\'/\')\n    sr_need(parts and all(part not in (\'\',\'.\',\'..\') for part in parts),code)\n    return value\n\n\ndef sr_timestamp(value, code):\n    sr_text(value,40,code)\n    match = re.fullmatch(r\'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,9}))?(?:Z|\\+00:00)\',value)\n    sr_need(match is not None,code)\n    try:\n        stamp = datetime.datetime(*(int(x) for x in match.groups()[:6]),tzinfo=datetime.timezone.utc)\n    except ValueError: raise SRRejected(code) from None\n    sr_need(stamp.year > 1,code)\n    return stamp,int((match.group(7) or \'\').ljust(9,\'0\') or \'0\')\n\n\ndef sr_name(value, code, python=False):\n    sr_text(value,256,code)\n    sr_need(re.fullmatch(r\'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._+:-]*\',value) is not None,code)\n    if python:\n        sr_need(re.fullmatch(r\'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\',value) is not None,code)\n        return re.sub(r\'[-_.]+\',\'-\',value).lower()\n    return value\n\n\ndef sr_version(value, code, empty=False):\n    sr_text(value,512,code,empty)\n    sr_need(not value or re.fullmatch(r\'[A-Za-z0-9][A-Za-z0-9._+!~:,<>=|* -]*\',value) is not None,code)\n    return value\n\n\ndef sr_pairs(packages, code, python=False):\n    sr_need(type(packages) is list and len(packages) <= 200000,code)\n    result = set()\n    for row in packages:\n        sr_need(type(row) is dict and \'Name\' in row and \'Version\' in row,code)\n        result.add((sr_name(row[\'Name\'],code,python),sr_version(row[\'Version\'],code)))\n    return result\n\n\ndef sr_inventory_hash(pairs):\n    return sr_digest(sr_canonical([list(row) for row in sorted(pairs)]))\n\n\ndef sr_numeric_version(value):\n    sr_need(type(value) is str and re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',value) is not None,\'PYTHON\')\n    return tuple(int(x) for x in value.split(\'.\'))\n\n\ndef sr_satisfies(version, specifier):\n    actual = sr_numeric_version(version)\n    sr_text(specifier,512,\'PYTHON\')\n    for item in specifier.split(\',\'):\n        match = re.fullmatch(r\'\\s*(>=|<=|==|!=|~=|>|<)\\s*([0-9]+(?:\\.[0-9]+)*(?:\\.\\*)?)\\s*\',item)\n        sr_need(match is not None,\'PYTHON\')\n        op, text = match.groups(); wild = text.endswith(\'.*\')\n        wanted = sr_numeric_version(text[:-2] if wild else text)\n        width = max(len(actual),len(wanted)); a = actual+(0,)*(width-len(actual)); b = wanted+(0,)*(width-len(wanted))\n        if wild:\n            sr_need(op in (\'==\',\'!=\'),\'PYTHON\'); equal = actual[:len(wanted)] == wanted\n            ok = equal if op == \'==\' else not equal\n        elif op == \'~=\':\n            sr_need(len(wanted) >= 2,\'PYTHON\')\n            upper = (wanted[0]+1,) if len(wanted) == 2 else wanted[:-2]+(wanted[-2]+1,)\n            u = upper+(0,)*(width-len(upper)); ok = a >= b and a < u\n        else:\n            ok = {\'>=\':a>=b,\'<=\':a<=b,\'==\':a==b,\'!=\':a!=b,\'>\':a>b,\'<\':a<b}[op]\n        sr_need(ok,\'PYTHON\')\n\n\ndef sr_requirement(value):\n    sr_text(value,1024,\'PYTHON\')\n    match = re.fullmatch(r\'([A-Za-z0-9][A-Za-z0-9._-]*)(.*)\',value)\n    sr_need(match is not None and not any(c in match.group(2) for c in \';[]@\'),\'PYTHON\')\n    name = sr_name(match.group(1),\'PYTHON\',True); spec = match.group(2).strip()\n    return name,spec\n\n\ndef sr_runtime_lock(lock_raw, project_raw, actual_python):\n    try:\n        lock = tomllib.loads(lock_raw.decode(\'utf-8\',\'strict\'))\n        manifest = tomllib.loads(project_raw.decode(\'utf-8\',\'strict\'))\n    except (ValueError,UnicodeError,RecursionError): raise SRRejected(\'PYTHON\') from None\n    sr_walk(lock,\'PYTHON\'); sr_walk(manifest,\'PYTHON\')\n    sr_need(type(lock) is dict and type(manifest) is dict,\'PYTHON\')\n    sr_int(lock.get(\'version\'),1,1,\'PYTHON\'); sr_need(type(lock.get(\'revision\')) is int and lock[\'revision\'] in (3,5),\'PYTHON\')\n    project = manifest.get(\'project\'); sr_need(type(project) is dict,\'PYTHON\')\n    sr_need(manifest.get(\'tool\',{}).get(\'uv\',{}).get(\'package\') is False,\'PYTHON\')\n    sr_need(not manifest.get(\'dependency-groups\') and not project.get(\'optional-dependencies\') and\n            not lock.get(\'resolution-markers\') and not lock.get(\'supported-markers\'),\'PYTHON\')\n    sr_satisfies(actual_python,project.get(\'requires-python\')); sr_satisfies(actual_python,lock.get(\'requires-python\'))\n    root_name = sr_name(project.get(\'name\'),\'PYTHON\',True); root_version = sr_version(project.get(\'version\'),\'PYTHON\')\n    sr_numeric_version(root_version)\n    packages = lock.get(\'package\'); sr_need(type(packages) is list and 1 <= len(packages) <= 100000,\'PYTHON\')\n    by_name = {}; root = None\n    for row in packages:\n        sr_need(type(row) is dict,\'PYTHON\')\n        name = sr_name(row.get(\'name\'),\'PYTHON\',True); version = sr_version(row.get(\'version\'),\'PYTHON\')\n        sr_numeric_version(version); sr_need(name not in by_name,\'PYTHON\'); by_name[name] = row\n        sr_need(not any(row.get(k) for k in (\'optional-dependencies\',\'dev-dependencies\',\'marker\',\'resolution-markers\')),\'PYTHON\')\n        if row.get(\'source\') == {\'virtual\':\'.\'}:\n            sr_need(root is None and name == root_name and version == root_version,\'PYTHON\'); root = row\n        else:\n            sr_need(row.get(\'source\') == {\'registry\':\'https://pypi.org/simple\'},\'PYTHON\')\n    sr_need(root is not None,\'PYTHON\')\n    def edges(row):\n        values = row.get(\'dependencies\',[]); sr_need(type(values) is list,\'PYTHON\'); found = []\n        for edge in values:\n            sr_closed(edge,(\'name\',),\'PYTHON\'); name = sr_name(edge[\'name\'],\'PYTHON\',True)\n            sr_need(name in by_name and name != root_name and name not in found,\'PYTHON\'); found.append(name)\n        return found\n    roots = edges(root); declarations = project.get(\'dependencies\')\n    sr_need(type(declarations) is list and declarations,\'PYTHON\')\n    required = {}\n    for declaration in declarations:\n        name,spec = sr_requirement(declaration); sr_need(name in by_name and name not in required,\'PYTHON\')\n        if spec: sr_satisfies(by_name[name][\'version\'],spec)\n        required[name] = spec\n    sr_need(set(roots) == set(required),\'PYTHON\')\n    declared = root.get(\'metadata\',{}).get(\'requires-dist\')\n    sr_need(type(declared) is list and len(declared) == len(required),\'PYTHON\')\n    metadata_names = set()\n    for row in declared:\n        sr_closed(row,(\'name\',\'specifier\'),\'PYTHON\'); name = sr_name(row[\'name\'],\'PYTHON\',True)\n        sr_need(name in required and name not in metadata_names and row[\'specifier\'] == required[name],\'PYTHON\')\n        metadata_names.add(name)\n    pending = list(roots); selected = set()\n    while pending:\n        name = pending.pop()\n        if name in selected: continue\n        selected.add(name); pending.extend(edges(by_name[name]))\n    sr_need(selected == set(by_name)-{root_name},\'PYTHON\')\n    return {(name,by_name[name][\'version\']) for name in selected}\n\n\ndef sr_member(row, code):\n    sr_closed(row,(\'path\',\'sha256\',\'bytes\',\'data_b64\'),code)\n    sr_path(row[\'path\'],code); size = sr_int(row[\'bytes\'],1,SR_MEMBER_MAX,code)\n    raw = sr_b64(row[\'data_b64\'],SR_MEMBER_MAX,code)\n    sr_need(len(raw) == size and sr_digest(raw) == sr_hash(row[\'sha256\'],code),code)\n    return raw\n\n\ndef sr_metadata_rows(rows):\n    sr_need(type(rows) is list and 1 <= len(rows) <= 200000,\'PYTHON\')\n    paths = set(); all_pairs = set(); venv_pairs = set(); venv_names = {}\n    for row in rows:\n        raw = sr_member(row,\'PYTHON\'); path = row[\'path\']\n        sr_need(path not in paths and re.search(r\'/[^/]+\\.dist-info/METADATA$\',path) is not None,\'PYTHON\'); paths.add(path)\n        try: text = raw.decode(\'utf-8\',\'strict\')\n        except UnicodeError: raise SRRejected(\'PYTHON\') from None\n        sr_text(text,SR_MEMBER_MAX,\'PYTHON\')\n        headers = {}; last = None\n        for line in text.splitlines():\n            if line == \'\': break\n            if line[:1] in (\' \',\'\\t\'):\n                sr_need(last is not None,\'PYTHON\'); headers[last][-1] += \'\\n\'+line; continue\n            sr_need(\':\' in line,\'PYTHON\'); key,value = line.split(\':\',1); key = key.lower()\n            sr_need(re.fullmatch(\'[a-z0-9-]+\',key) is not None,\'PYTHON\')\n            headers.setdefault(key,[]).append(value.strip()); last = key\n        sr_need(len(headers.get(\'name\',[])) == len(headers.get(\'version\',[])) == 1,\'PYTHON\')\n        pair = (sr_name(headers[\'name\'][0],\'PYTHON\',True),sr_version(headers[\'version\'][0],\'PYTHON\'))\n        all_pairs.add(pair)\n        if path.startswith(SR_VENV+\'/\'):\n            sr_need(pair[0] not in venv_names,\'PYTHON\'); venv_names[pair[0]] = pair[1]; venv_pairs.add(pair)\n    sr_need(all_pairs and venv_pairs,\'PYTHON\')\n    return all_pairs,venv_pairs\n\n\ndef sr_os_release(row):\n    sr_closed(row,(\'path\',\'sha256\',\'data_b64\'),\'OS\'); sr_path(row[\'path\'],\'OS\')\n    raw = sr_b64(row[\'data_b64\'],SR_MEMBER_MAX,\'OS\'); sr_need(sr_digest(raw) == sr_hash(row[\'sha256\'],\'OS\'),\'OS\')\n    try: text = raw.decode(\'utf-8\',\'strict\')\n    except UnicodeError: raise SRRejected(\'OS\') from None\n    sr_text(text,SR_MEMBER_MAX,\'OS\'); values = {}\n    for line in text.splitlines():\n        if not line.strip() or line.lstrip().startswith(\'#\'): continue\n        sr_need(\'=\' in line,\'OS\'); key,value = line.split(\'=\',1)\n        sr_need(re.fullmatch(\'[A-Z_][A-Z0-9_]*\',key) is not None and key not in values,\'OS\')\n        if value.startswith((\'"\',"\'")):\n            sr_need(len(value) >= 2 and value[-1] == value[0],\'OS\'); value = value[1:-1]\n        sr_need(\'\\\\\' not in value and \'\\0\' not in value,\'OS\'); values[key] = value\n    sr_need(values.get(\'ID\') == \'debian\' and re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',values.get(\'VERSION_ID\',\'\')) is not None,\'OS\')\n    return values[\'VERSION_ID\'].split(\'.\')[0]\n\n\ndef sr_node_rows(node):\n    sr_closed(node,(\'applicability\',\'metadata\',\'runtime_paths\'),\'NODE\')\n    sr_need(node[\'applicability\'] in (\'ABSENT\',\'PRESENT\') and type(node[\'metadata\']) is list and type(node[\'runtime_paths\']) is list,\'NODE\')\n    paths = set(); pairs = set()\n    for path in node[\'runtime_paths\']:\n        sr_path(path,\'NODE\'); sr_need(path not in paths,\'NODE\'); paths.add(path)\n    files = set()\n    for row in node[\'metadata\']:\n        raw = sr_member(row,\'NODE\'); sr_need(row[\'path\'] not in files and row[\'path\'].endswith(\'/package.json\') and \'/node_modules/\' in row[\'path\'],\'NODE\')\n        files.add(row[\'path\']); doc = sr_json(raw,SR_MEMBER_MAX); sr_need(type(doc) is dict,\'NODE\')\n        pairs.add((sr_name(doc.get(\'name\'),\'NODE\'),sr_version(doc.get(\'version\'),\'NODE\')))\n    if node[\'applicability\'] == \'ABSENT\': sr_need(not paths and not pairs and not files,\'NODE\')\n    else: sr_need(pairs and files,\'NODE\')\n    return pairs\n\n\ndef sr_empty_summary():\n    return {\'schemaVersion\':1,\'scope\':SR_SCOPE,\'status\':\'ERROR\',\'category\':\'BOOTSTRAP\',\n            \'identities\':None,\'db\':None,\'coverage\':None,\'actual_exit\':None,\'findings\':None,\'cleanup\':False}\n\n\ndef sr_finding(row):\n    sr_need(type(row) is dict,\'JSON\')\n    advisory = sr_text(row.get(\'VulnerabilityID\'),128,\'JSON\')\n    sr_need(re.fullmatch(\'[A-Za-z0-9][A-Za-z0-9._:+-]*\',advisory) is not None,\'JSON\')\n    package = sr_name(row.get(\'PkgName\'),\'JSON\'); installed = sr_version(row.get(\'InstalledVersion\'),\'JSON\')\n    fixed = sr_version(row.get(\'FixedVersion\',\'\'),\'JSON\',True)\n    severity = row.get(\'Severity\'); sr_need(severity in (\'HIGH\',\'CRITICAL\'),\'JSON\')\n    status = row.get(\'Status\')\n    sr_need(status is None or type(status) is str and status in (\'\',\'unknown\',\'affected\',\'fixed\',\'under_investigation\',\'will_not_fix\',\'fix_deferred\',\'end_of_life\'),\'JSON\')\n    return {\'id\':advisory,\'pkg\':package,\'installed\':installed,\'fixed\':fixed,\'severity\':severity,\'status\':status}\n\n\ndef sr_validate_summary(value):\n    sr_closed(value,(\'schemaVersion\',\'scope\',\'status\',\'category\',\'identities\',\'db\',\'coverage\',\'actual_exit\',\'findings\',\'cleanup\'),\'JSON\')\n    sr_int(value[\'schemaVersion\'],1,1,\'JSON\'); sr_need(value[\'scope\'] == SR_SCOPE and value[\'status\'] in (\'PASS\',\'FINDINGS\',\'ERROR\') and type(value[\'cleanup\']) is bool,\'JSON\')\n    if value[\'actual_exit\'] is not None: sr_int(value[\'actual_exit\'],0,255,\'JSON\')\n    ids = value[\'identities\']\n    if ids is not None:\n        sr_closed(ids,SR_ID_KEYS,\'JSON\')\n        for key,item in ids.items():\n            if item is None: continue\n            if key == \'source_head\': sr_need(type(item) is str and re.fullmatch(\'[0-9a-f]{40}\',item) is not None,\'JSON\')\n            elif key in (\'image_id\',\'scanner_image_id\',\'uv_material_digest\',\'uv_platform_manifest_digest\'): sr_image(item,\'JSON\')\n            else: sr_hash(item,\'JSON\')\n        if ids[\'image_id\'] is not None and ids[\'scanner_image_id\'] is not None: sr_need(ids[\'image_id\'] != ids[\'scanner_image_id\'],\'JSON\')\n    db = value[\'db\']\n    if db is not None:\n        sr_closed(db,(\'scanner_version\',\'schema_version\',\'updated_at\',\'downloaded_at\',\'next_update\',\'fresh_cache\',\'download_in_scan_window\'),\'JSON\')\n        sr_need(db[\'scanner_version\'] == \'0.57.1\' and db[\'fresh_cache\'] is db[\'download_in_scan_window\'] is True,\'JSON\')\n        sr_int(db[\'schema_version\'],2,2,\'JSON\')\n        for key in (\'updated_at\',\'downloaded_at\',\'next_update\'): sr_timestamp(db[key],\'JSON\')\n        sr_need(sr_timestamp(db[\'updated_at\'],\'JSON\') < sr_timestamp(db[\'next_update\'],\'JSON\'),\'JSON\')\n    coverage = value[\'coverage\']\n    if coverage is not None:\n        sr_closed(coverage,(\'report_schema_version\',\'os\',\'python\',\'rust\',\'node\',\'limits\'),\'JSON\')\n        sr_int(coverage[\'report_schema_version\'],2,2,\'JSON\'); sr_need(coverage[\'limits\'] == SR_LIMITS,\'JSON\')\n        osdata = coverage[\'os\']; sr_closed(osdata,(\'family\',\'name\',\'supported_by_tagged_scanner\',\'eosl\',\'package_count\',\'inventory_sha256\'),\'JSON\')\n        sr_need(osdata[\'family\'] == \'debian\' and type(osdata[\'name\']) is str and re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',osdata[\'name\']) is not None and\n                osdata[\'supported_by_tagged_scanner\'] is True and osdata[\'eosl\'] is False,\'JSON\')\n        sr_int(osdata[\'package_count\'],1,200000,\'JSON\'); sr_hash(osdata[\'inventory_sha256\'],\'JSON\')\n        py = coverage[\'python\']; sr_closed(py,(\'metadata_files\',\'installed_pairs\',\'venv_pairs\',\'lock_runtime_pairs\',\'reported_pairs\',\'inventory_sha256\',\'venv_inventory_sha256\',\'lock_inventory_sha256\'),\'JSON\')\n        for key in (\'metadata_files\',\'installed_pairs\',\'venv_pairs\',\'lock_runtime_pairs\',\'reported_pairs\'): sr_int(py[key],1,200000,\'JSON\')\n        sr_need(py[\'lock_runtime_pairs\'] <= py[\'venv_pairs\'] <= py[\'installed_pairs\'] == py[\'reported_pairs\'] <= py[\'metadata_files\'],\'JSON\')\n        for key in (\'inventory_sha256\',\'venv_inventory_sha256\',\'lock_inventory_sha256\'): sr_hash(py[key],\'JSON\')\n        sr_closed(coverage[\'rust\'],(\'uv\',\'uvx\'),\'JSON\')\n        for row in coverage[\'rust\'].values():\n            sr_closed(row,(\'binary_sha256\',\'package_count\',\'inventory_sha256\'),\'JSON\'); sr_hash(row[\'binary_sha256\'],\'JSON\')\n            sr_hash(row[\'inventory_sha256\'],\'JSON\'); sr_int(row[\'package_count\'],1,200000,\'JSON\')\n        node = coverage[\'node\']; sr_closed(node,(\'applicability\',\'metadata_files\',\'installed_pairs\',\'reported_pairs\',\'inventory_sha256\'),\'JSON\')\n        sr_need(node[\'applicability\'] in (\'ABSENT\',\'PRESENT\'),\'JSON\')\n        for key in (\'metadata_files\',\'installed_pairs\',\'reported_pairs\'): sr_int(node[key],0,200000,\'JSON\')\n        sr_hash(node[\'inventory_sha256\'],\'JSON\'); sr_need(node[\'installed_pairs\'] == node[\'reported_pairs\'] <= node[\'metadata_files\'],\'JSON\')\n        sr_need(node[\'installed_pairs\'] > 0 if node[\'applicability\'] == \'PRESENT\' else node[\'metadata_files\'] == node[\'installed_pairs\'] == 0,\'JSON\')\n    findings = value[\'findings\']\n    if findings is not None:\n        sr_need(type(findings) is list and len(findings) <= 8192,\'JSON\')\n        for row in findings:\n            sr_closed(row,(\'id\',\'pkg\',\'installed\',\'fixed\',\'severity\',\'status\'),\'JSON\')\n            mapped = sr_finding({\'VulnerabilityID\':row[\'id\'],\'PkgName\':row[\'pkg\'],\'InstalledVersion\':row[\'installed\'],\n                                 \'FixedVersion\':row[\'fixed\'],\'Severity\':row[\'severity\'],\'Status\':row[\'status\']})\n            sr_need(mapped == row,\'JSON\')\n    if value[\'status\'] == \'ERROR\': sr_need(value[\'category\'] in SR_ERRORS,\'JSON\')\n    else:\n        sr_need(ids is not None and all(item is not None for item in ids.values()) and db is not None and coverage is not None and\n                findings is not None and value[\'cleanup\'] is True,\'JSON\')\n        if value[\'status\'] == \'PASS\': sr_need(value[\'category\'] == \'OK\' and value[\'actual_exit\'] == 0 and findings == [],\'JSON\')\n        else: sr_need(value[\'category\'] == \'HIGH_CRITICAL\' and value[\'actual_exit\'] == 1 and len(findings) > 0,\'JSON\')\n\n\ndef validate_safe_summary(raw):\n    """Return only a validated closed safe DTO, or fixed invalid/null."""\n    try:\n        value = sr_json(raw,SR_SUMMARY_MAX); sr_validate_summary(value)\n        return {\'valid\':True,\'report\':value}\n    except Exception:\n        return {\'valid\':False,\'report\':None}\n\n\ndef sr_finish(out):\n    try:\n        sr_validate_summary(out)\n        if len(sr_canonical(out)) <= SR_SUMMARY_MAX: return out\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = \'OVERFLOW\'; out[\'findings\'] = None\n        sr_validate_summary(out)\n        if len(sr_canonical(out)) <= SR_SUMMARY_MAX: return out\n    except Exception:\n        pass\n    empty = sr_empty_summary(); empty[\'category\'] = \'INTERNAL\'\n    return empty\n\n\ndef validate_scan_evidence(evidence, report_raw, version_raw):\n    """Total pure reducer; ERROR outranks findings and no raw field is reflected."""\n    out = sr_empty_summary()\n    try:\n        sr_closed(evidence,(\'schemaVersion\',\'source\',\'build\',\'image\',\'archive\',\'scanner\',\'witness\',\'inputs\',\'final\',\'error_codes\'),\'BOOTSTRAP\')\n        sr_walk(evidence); sr_need(len(sr_canonical(evidence)) <= SR_WITNESS_MAX,\'OVERFLOW\')\n        sr_int(evidence[\'schemaVersion\'],1,1,\'BOOTSTRAP\')\n        errors = evidence[\'error_codes\']; sr_need(type(errors) is list and len(errors) <= len(SR_ERRORS) and all(type(x) is str and x in SR_ERRORS for x in errors),\'BOOTSTRAP\')\n        scanner = evidence[\'scanner\']\n        if type(scanner) is dict and type(scanner.get(\'scan_exit\')) is int and 0 <= scanner[\'scan_exit\'] <= 255: out[\'actual_exit\'] = scanner[\'scan_exit\']\n        if errors: raise SRRejected(next(code for code in SR_ERRORS if code in errors))\n        final = evidence[\'final\']; sr_closed(final,(\'archive_unchanged\',\'cancelled\',\'containers_removed\',\'image_unchanged\',\'owned_cli_drain\',\'owned_image_removed\',\'private_context_removed\',\'source_unchanged\',\'uncertain\'),\'CLEANUP\')\n        sr_need(all(type(x) is bool for x in final.values()),\'CLEANUP\')\n        sr_need(not final[\'cancelled\'],\'CANCELLED\')\n        sr_need(not final[\'uncertain\'] and all(final[k] for k in (\'owned_cli_drain\',\'containers_removed\',\'owned_image_removed\',\'private_context_removed\')),\'CLEANUP\'); out[\'cleanup\'] = True\n        sr_need(final[\'source_unchanged\'],\'SOURCE\'); sr_need(final[\'image_unchanged\'],\'LINEAGE\'); sr_need(final[\'archive_unchanged\'],\'ARCHIVE\')\n        source = evidence[\'source\']; sr_closed(source,(\'before\',\'after\',\'context_sha256\',\'head\'),\'SOURCE\')\n        sr_need(type(source[\'head\']) is str and re.fullmatch(\'[0-9a-f]{40}\',source[\'head\']) is not None,\'SOURCE\')\n        for values in (source[\'before\'],source[\'after\']):\n            sr_need(type(values) is dict and SR_REQUIRED_SOURCE <= set(values) and len(values) <= 200000,\'SOURCE\')\n            for path,row in values.items():\n                sr_path(path,\'SOURCE\',False); sr_closed(row,(\'sha256\',\'bytes\'),\'SOURCE\'); sr_hash(row[\'sha256\'],\'SOURCE\'); sr_int(row[\'bytes\'],0,2**63-1,\'SOURCE\')\n        sr_need(sr_canonical(source[\'before\']) == sr_canonical(source[\'after\']) and\n                sr_digest(sr_canonical(source[\'before\'])) == sr_hash(source[\'context_sha256\'],\'SOURCE\'),\'SOURCE\')\n        image = evidence[\'image\']; sr_closed(image,(\'id\',\'iid_matches\',\'os\',\'architecture\',\'variant\'),\'LINEAGE\')\n        sr_image(image[\'id\'],\'LINEAGE\'); sr_text(image[\'variant\'],32,\'LINEAGE\',True)\n        sr_need(image[\'iid_matches\'] is True and image[\'os\'] == \'linux\' and image[\'architecture\'] == \'amd64\',\'LINEAGE\')\n        build = evidence[\'build\']; sr_closed(build,(\'actual_exit\',\'metadata_config_image_id\',\'metadata_sha256\',\'uv\'),\'BUILD\')\n        sr_int(build[\'actual_exit\'],0,0,\'BUILD\'); sr_hash(build[\'metadata_sha256\'],\'BUILD\'); sr_need(build[\'metadata_config_image_id\'] == image[\'id\'],\'LINEAGE\')\n        uv = build[\'uv\']; sr_closed(uv,(\'actual_build_material_join\',\'index_digest\',\'index_sha256\',\'manifest_sha256\',\'material_digest\',\'material_uri\',\'platform\',\'platform_manifest_digest\',\'reference\'),\'LINEAGE\')\n        sr_need(uv[\'actual_build_material_join\'] is True and uv[\'reference\'] == \'ghcr.io/astral-sh/uv:0.12.8\' and uv[\'platform\'] == \'linux/amd64\',\'LINEAGE\')\n        sr_text(uv[\'material_uri\'],4096,\'LINEAGE\'); sr_image(uv[\'material_digest\'],\'LINEAGE\'); sr_image(uv[\'platform_manifest_digest\'],\'LINEAGE\'); sr_hash(uv[\'manifest_sha256\'],\'LINEAGE\')\n        sr_need(uv[\'manifest_sha256\'] == uv[\'platform_manifest_digest\'][7:],\'LINEAGE\')\n        if uv[\'index_digest\'] is None:\n            sr_need(uv[\'index_sha256\'] is None and uv[\'material_digest\'] == uv[\'platform_manifest_digest\'],\'LINEAGE\')\n        else:\n            sr_image(uv[\'index_digest\'],\'LINEAGE\'); sr_need(sr_hash(uv[\'index_sha256\'],\'LINEAGE\') == uv[\'index_digest\'][7:] and uv[\'material_digest\'] == uv[\'index_digest\'],\'LINEAGE\')\n        archive = evidence[\'archive\']; sr_closed(archive,(\'bytes\',\'image_id\',\'sha256\',\'unchanged\'),\'ARCHIVE\')\n        sr_int(archive[\'bytes\'],1,4294967296,\'ARCHIVE\'); sr_hash(archive[\'sha256\'],\'ARCHIVE\'); sr_need(archive[\'image_id\'] == image[\'id\'] and archive[\'unchanged\'] is True,\'ARCHIVE\')\n        sr_closed(scanner,(\'config_sha256\',\'db_download_scan_only\',\'empty_cache_before\',\'help_flags\',\'help_sha256\',\'ignore_sha256\',\'image_id\',\'same_cache\',\'scan_exit\',\'scan_utc\',\'version_after_exit\',\'version_after_utc\',\'version_before_b64\',\'version_before_exit\'),\'SCANNER\')\n        sr_image(scanner[\'image_id\'],\'TOOL\'); sr_need(scanner[\'image_id\'] != image[\'id\'],\'TOOL\'); sr_hash(scanner[\'help_sha256\'],\'TOOL\')\n        sr_need(type(scanner[\'help_flags\']) is list and all(type(x) is str for x in scanner[\'help_flags\']) and len(scanner[\'help_flags\']) == len(set(scanner[\'help_flags\'])) and SR_HELP_FLAGS <= set(scanner[\'help_flags\']),\'TOOL\')\n        sr_need(scanner[\'config_sha256\'] == sr_digest(b\'{}\\n\') and scanner[\'ignore_sha256\'] == sr_digest(b\'\') and scanner[\'db_download_scan_only\'] is True,\'SCANNER\')\n        sr_need(scanner[\'empty_cache_before\'] is scanner[\'same_cache\'] is True,\'DB\')\n        sr_int(scanner[\'version_before_exit\'],0,0,\'TOOL\'); sr_int(scanner[\'version_after_exit\'],0,0,\'DB\')\n        before = sr_json(sr_b64(scanner[\'version_before_b64\'],SR_VERSION_MAX,\'DB\'),SR_VERSION_MAX)\n        sr_need(type(before) is dict and before.get(\'Version\') == \'0.57.1\',\'TOOL\')\n        sr_need(\'VulnerabilityDB\' not in before or before[\'VulnerabilityDB\'] is None,\'DB\')\n        scan_time = sr_timestamp(scanner[\'scan_utc\'],\'DB\'); after_time = sr_timestamp(scanner[\'version_after_utc\'],\'DB\'); sr_need(scan_time <= after_time,\'DB\')\n        sr_int(scanner[\'scan_exit\'],0,255,\'EXIT\')\n        witness = evidence[\'witness\']; sr_closed(witness,(\'complete\',\'image_id\',\'member_count\',\'node\',\'os_release\',\'python\',\'rootfs_bytes\',\'rootfs_sha256\',\'uv\',\'uvx\'),\'WITNESS\')\n        sr_need(witness[\'complete\'] is True and witness[\'image_id\'] == image[\'id\'],\'WITNESS\'); sr_int(witness[\'member_count\'],1,200000,\'WITNESS\')\n        sr_int(witness[\'rootfs_bytes\'],1,4294967296,\'WITNESS\'); sr_hash(witness[\'rootfs_sha256\'],\'WITNESS\')\n        sr_need(type(report_raw) is bytes and 0 < len(report_raw) <= SR_RAW_MAX and type(version_raw) is bytes and 0 < len(version_raw) <= SR_VERSION_MAX,\'JSON\')\n        out[\'identities\'] = {\'source_head\':source[\'head\'],\'source_sha256\':source[\'context_sha256\'],\'image_id\':image[\'id\'],\n            \'archive_sha256\':archive[\'sha256\'],\'scanner_image_id\':scanner[\'image_id\'],\'report_sha256\':sr_digest(report_raw),\n            \'version_sha256\':sr_digest(version_raw),\'witness_sha256\':sr_digest(sr_canonical(evidence)),\n            \'build_metadata_sha256\':build[\'metadata_sha256\'],\'uv_material_digest\':uv[\'material_digest\'],\'uv_platform_manifest_digest\':uv[\'platform_manifest_digest\']}\n        version = sr_json(version_raw,SR_VERSION_MAX); sr_need(type(version) is dict and version.get(\'Version\') == \'0.57.1\',\'TOOL\')\n        db = version.get(\'VulnerabilityDB\'); sr_need(type(db) is dict,\'DB\'); sr_int(db.get(\'Version\'),2,2,\'DB\')\n        for key in (\'UpdatedAt\',\'DownloadedAt\',\'NextUpdate\'): sr_timestamp(db.get(key),\'DB\')\n        sr_need(scan_time <= sr_timestamp(db[\'DownloadedAt\'],\'DB\') <= after_time and sr_timestamp(db[\'UpdatedAt\'],\'DB\') < sr_timestamp(db[\'NextUpdate\'],\'DB\'),\'DB\')\n        out[\'db\'] = {\'scanner_version\':\'0.57.1\',\'schema_version\':2,\'updated_at\':db[\'UpdatedAt\'],\'downloaded_at\':db[\'DownloadedAt\'],\'next_update\':db[\'NextUpdate\'],\'fresh_cache\':True,\'download_in_scan_window\':True}\n        report = sr_json(report_raw,SR_RAW_MAX); sr_need(type(report) is dict,\'JSON\'); sr_int(report.get(\'SchemaVersion\'),2,2,\'JSON\')\n        metadata = report.get(\'Metadata\'); sr_need(type(metadata) is dict and metadata.get(\'ImageID\') == image[\'id\'],\'SCANNER\')\n        osmeta = metadata.get(\'OS\'); sr_need(type(osmeta) is dict and osmeta.get(\'Family\') == \'debian\',\'OS\')\n        osname = sr_text(osmeta.get(\'Name\'),32,\'OS\'); sr_need(re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',osname) is not None,\'OS\')\n        major = sr_os_release(witness[\'os_release\']); sr_need(major == osname.split(\'.\')[0] and major in SR_DEBIAN_EOL and scan_time < sr_timestamp(SR_DEBIAN_EOL[major],\'OS\'),\'OS\')\n        sr_need(\'EOSL\' not in osmeta or type(osmeta[\'EOSL\']) is bool and osmeta[\'EOSL\'] is False,\'OS\')\n        sr_need(\'extended\' not in osmeta or osmeta[\'extended\'] is False,\'OS\')\n        results = report.get(\'Results\'); sr_need(type(results) is list and results,\'JSON\')\n        inventories = {\'os\':set(),\'python\':set(),\'node\':set(),\'uv\':set(),\'uvx\':set()}; aliases = {}; rust_rows = {}\n        for role in (\'uv\',\'uvx\'):\n            row = witness[role]; sr_closed(row,(\'requested_path\',\'resolved_path\',\'aliases\',\'sha256\',\'bytes\',\'mode\',\'executable\'),\'RUST\')\n            sr_need(row[\'requested_path\'] == \'/bin/\'+role and row[\'executable\'] is True,\'RUST\'); sr_path(row[\'resolved_path\'],\'RUST\')\n            sr_int(row[\'bytes\'],1,268435456,\'RUST\'); mode = sr_int(row[\'mode\'],0,0o7777,\'RUST\'); sr_need(mode & 0o111 and not mode & 0o022,\'RUST\'); sr_hash(row[\'sha256\'],\'RUST\')\n            sr_need(type(row[\'aliases\']) is list and 1 <= len(row[\'aliases\']) <= 32 and len(row[\'aliases\']) == len(set(row[\'aliases\'])),\'RUST\')\n            for path in row[\'aliases\']: sr_path(path,\'RUST\')\n            sr_need(row[\'requested_path\'] in row[\'aliases\'] and row[\'resolved_path\'] in row[\'aliases\'],\'RUST\')\n            aliases[role] = set(row[\'aliases\']); rust_rows[role] = row\n        sr_need(aliases[\'uv\'].isdisjoint(aliases[\'uvx\']),\'RUST\')\n        findings = []; seen_rust = set()\n        for result in results:\n            sr_need(type(result) is dict,\'JSON\'); kind = result.get(\'Type\'); cls = result.get(\'Class\')\n            sr_text(kind,128,\'JSON\'); sr_text(cls,128,\'JSON\'); sr_text(result.get(\'Target\'),4096,\'JSON\',True)\n            code = \'OS\' if cls == \'os-pkgs\' else \'PYTHON\' if kind == \'python-pkg\' else \'RUST\' if kind == \'rustbinary\' else \'NODE\' if kind == \'node-pkg\' else \'JSON\'\n            packages = sr_pairs(result.get(\'Packages\',[]),code,kind == \'python-pkg\')\n            if cls == \'os-pkgs\':\n                sr_need(kind == \'debian\' and packages,\'OS\'); inventories[\'os\'].update(packages)\n            elif kind in (\'python-pkg\',\'node-pkg\',\'rustbinary\'):\n                sr_need(cls == \'lang-pkgs\',code)\n                if kind == \'python-pkg\': inventories[\'python\'].update(packages)\n                elif kind == \'node-pkg\': inventories[\'node\'].update(packages)\n                else:\n                    target = \'/\'+result[\'Target\'].lstrip(\'/\'); sr_path(target,\'RUST\')\n                    matching = [role for role in aliases if target in aliases[role]]\n                    sr_need(len(matching) <= 1,\'RUST\')\n                    if matching:\n                        role = matching[0]; sr_need(role not in seen_rust and packages,\'RUST\'); seen_rust.add(role); inventories[role] = packages\n            rows = result.get(\'Vulnerabilities\',[]); sr_need(type(rows) is list,\'JSON\')\n            for row in rows:\n                finding = sr_finding(row)\n                sr_need((sr_name(finding[\'pkg\'],\'JSON\',kind == \'python-pkg\'),finding[\'installed\']) in packages,\'JSON\')\n                findings.append(finding); sr_need(len(findings) <= 8192,\'OVERFLOW\')\n        sr_need(inventories[\'os\'] and inventories[\'python\'] and seen_rust == {\'uv\',\'uvx\'},\'OS\' if not inventories[\'os\'] else \'RUST\' if seen_rust != {\'uv\',\'uvx\'} else \'PYTHON\')\n        py = witness[\'python\']; sr_closed(py,(\'implementation\',\'metadata\',\'platform\',\'venv\',\'version\',\'version_metadata_sha256\'),\'PYTHON\')\n        sr_need(py[\'implementation\'] == \'cpython\' and py[\'venv\'] == SR_VENV and py[\'platform\'] == {\'os_name\':\'posix\',\'sys_platform\':\'linux\',\'platform_system\':\'Linux\',\'platform_machine\':\'x86_64\',\'platform_python_implementation\':\'CPython\'},\'PYTHON\')\n        sr_hash(py[\'version_metadata_sha256\'],\'PYTHON\'); python_version = sr_numeric_version(py[\'version\']); sr_need(len(python_version) == 3,\'PYTHON\')\n        installed,venv = sr_metadata_rows(py[\'metadata\']); sr_need(installed == inventories[\'python\'],\'PYTHON\')\n        inputs = evidence[\'inputs\']; sr_closed(inputs,(\'no_dev\',\'pyproject_b64\',\'selected_extras\',\'uv_lock_b64\'),\'PYTHON\')\n        sr_need(inputs[\'no_dev\'] is True and inputs[\'selected_extras\'] == [] and type(inputs[\'selected_extras\']) is list,\'PYTHON\')\n        lock_raw = sr_b64(inputs[\'uv_lock_b64\'],SR_MEMBER_MAX,\'PYTHON\'); project_raw = sr_b64(inputs[\'pyproject_b64\'],SR_MEMBER_MAX,\'PYTHON\')\n        for path,raw in ((SR_LOCK,lock_raw),(SR_PROJECT,project_raw)):\n            sr_need(source[\'before\'][path] == {\'sha256\':sr_digest(raw),\'bytes\':len(raw)},\'SOURCE\')\n        runtime = sr_runtime_lock(lock_raw,project_raw,py[\'version\']); sr_need(runtime and runtime <= venv,\'PYTHON\')\n        node_pairs = sr_node_rows(witness[\'node\']); sr_need(node_pairs == inventories[\'node\'],\'NODE\')\n        out[\'coverage\'] = {\'report_schema_version\':2,\n            \'os\':{\'family\':\'debian\',\'name\':osname,\'supported_by_tagged_scanner\':True,\'eosl\':False,\'package_count\':len(inventories[\'os\']),\'inventory_sha256\':sr_inventory_hash(inventories[\'os\'])},\n            \'python\':{\'metadata_files\':len(py[\'metadata\']),\'installed_pairs\':len(installed),\'venv_pairs\':len(venv),\'lock_runtime_pairs\':len(runtime),\'reported_pairs\':len(inventories[\'python\']),\'inventory_sha256\':sr_inventory_hash(installed),\'venv_inventory_sha256\':sr_inventory_hash(venv),\'lock_inventory_sha256\':sr_inventory_hash(runtime)},\n            \'rust\':{role:{\'binary_sha256\':rust_rows[role][\'sha256\'],\'package_count\':len(inventories[role]),\'inventory_sha256\':sr_inventory_hash(inventories[role])}for role in (\'uv\',\'uvx\')},\n            \'node\':{\'applicability\':witness[\'node\'][\'applicability\'],\'metadata_files\':len(witness[\'node\'][\'metadata\']),\'installed_pairs\':len(node_pairs),\'reported_pairs\':len(inventories[\'node\']),\'inventory_sha256\':sr_inventory_hash(node_pairs)},\'limits\':copy.deepcopy(SR_LIMITS)}\n        out[\'findings\'] = findings\n        if scanner[\'scan_exit\'] == 0 and not findings: out[\'status\'] = \'PASS\'; out[\'category\'] = \'OK\'\n        elif scanner[\'scan_exit\'] == 1 and findings: out[\'status\'] = \'FINDINGS\'; out[\'category\'] = \'HIGH_CRITICAL\'\n        else: raise SRRejected(\'EXIT\')\n    except SRRejected as error:\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = error.code\n    except Exception:\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = \'INTERNAL\'\n    return sr_finish(out)\n\n\ndef sr_data_controls():\n    """Run finite synthetic DATA through this same reducer; no SDK execution."""\n    passed = 0; count = 0\n    def b64(raw): return base64.b64encode(raw).decode(\'ascii\')\n    def member(path, raw):\n        return {\'path\':path,\'sha256\':sr_digest(raw),\'bytes\':len(raw),\'data_b64\':b64(raw)}\n    def fixture():\n        project = b\'\'\'[project]\nname = "synthetic-connector"\nversion = "1.0.0"\nrequires-python = ">=3.11,<3.12"\ndependencies = ["alpha>=1.0", "beta>=2.0"]\n[tool.uv]\npackage = false\n\'\'\'\n        lock = b\'\'\'version = 1\nrevision = 3\nrequires-python = "==3.11.*"\n[[package]]\nname = "alpha"\nversion = "1.2.0"\nsource = {registry = "https://pypi.org/simple"}\ndependencies = [{name = "beta"}]\n[[package]]\nname = "beta"\nversion = "2.0.0"\nsource = {registry = "https://pypi.org/simple"}\n[[package]]\nname = "synthetic-connector"\nversion = "1.0.0"\nsource = {virtual = "."}\ndependencies = [{name = "alpha"}, {name = "beta"}]\n[package.metadata]\nrequires-dist = [{name = "alpha", specifier = ">=1.0"}, {name = "beta", specifier = ">=2.0"}]\n\'\'\'\n        before = {path:{\'sha256\':sr_digest(b\'synthetic source\'), \'bytes\':16} for path in SR_REQUIRED_SOURCE}\n        before[SR_PROJECT] = {\'sha256\':sr_digest(project),\'bytes\':len(project)}\n        before[SR_LOCK] = {\'sha256\':sr_digest(lock),\'bytes\':len(lock)}\n        before[\'sycope/empty.py\'] = {\'sha256\':sr_digest(b\'\'),\'bytes\':0}\n        metadata = [member(SR_VENV+\'/lib/python3.11/site-packages/alpha-1.2.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: alpha\\nVersion: 1.2.0\\n\\nSynthetic only.\\n\'),\n                    member(SR_VENV+\'/lib/python3.11/site-packages/beta-2.0.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: beta\\nVersion: 2.0.0\\n\'),\n                    member(\'/usr/local/lib/python3.11/site-packages/global_tool-25.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: global-tool\\nVersion: 25.0\\n\')]\n        release = b\'ID=debian\\nVERSION_ID="13"\\nNAME="Debian GNU/Linux"\\n\'\n        image = \'sha256:\'+\'1\'*64; scanner = \'sha256:\'+\'2\'*64\n        e = {\'schemaVersion\':1,\n             \'source\':{\'before\':before,\'after\':copy.deepcopy(before),\'context_sha256\':sr_digest(sr_canonical(before)),\'head\':\'a\'*40},\n             \'build\':{\'actual_exit\':0,\'metadata_config_image_id\':image,\'metadata_sha256\':\'5\'*64,\n                      \'uv\':{\'actual_build_material_join\':True,\'index_digest\':\'sha256:\'+\'3\'*64,\'index_sha256\':\'3\'*64,\n                            \'manifest_sha256\':\'4\'*64,\'material_digest\':\'sha256:\'+\'3\'*64,\n                            \'material_uri\':\'pkg:docker/ghcr.io/astral-sh/uv@0.12.8?platform=linux%2Famd64\',\n                            \'platform\':\'linux/amd64\',\'platform_manifest_digest\':\'sha256:\'+\'4\'*64,\'reference\':\'ghcr.io/astral-sh/uv:0.12.8\'}},\n             \'image\':{\'id\':image,\'iid_matches\':True,\'os\':\'linux\',\'architecture\':\'amd64\',\'variant\':\'\'},\n             \'archive\':{\'bytes\':16384,\'image_id\':image,\'sha256\':\'6\'*64,\'unchanged\':True},\n             \'scanner\':{\'config_sha256\':sr_digest(b\'{}\\n\'),\'db_download_scan_only\':True,\'empty_cache_before\':True,\n                        \'help_flags\':sorted(SR_HELP_FLAGS),\'help_sha256\':\'7\'*64,\'ignore_sha256\':sr_digest(b\'\'),\'image_id\':scanner,\n                        \'same_cache\':True,\'scan_exit\':0,\'scan_utc\':\'2026-10-29T12:00:00Z\',\'version_after_exit\':0,\n                        \'version_after_utc\':\'2026-10-29T12:01:00Z\',\'version_before_b64\':b64(b\'{"Version":"0.57.1"}\'),\'version_before_exit\':0},\n             \'witness\':{\'complete\':True,\'image_id\':image,\'member_count\':100,\'rootfs_bytes\':32768,\'rootfs_sha256\':\'8\'*64,\n                        \'os_release\':{\'path\':\'/usr/lib/os-release\',\'sha256\':sr_digest(release),\'data_b64\':b64(release)},\n                        \'python\':{\'implementation\':\'cpython\',\'metadata\':metadata,\n                                  \'platform\':{\'os_name\':\'posix\',\'sys_platform\':\'linux\',\'platform_system\':\'Linux\',\'platform_machine\':\'x86_64\',\'platform_python_implementation\':\'CPython\'},\n                                  \'venv\':SR_VENV,\'version\':\'3.11.16\',\'version_metadata_sha256\':\'9\'*64},\n                        \'uv\':{\'requested_path\':\'/bin/uv\',\'resolved_path\':\'/usr/bin/uv\',\'aliases\':[\'/bin/uv\',\'/usr/bin/uv\'],\n                              \'sha256\':\'a\'*64,\'bytes\':4000,\'mode\':0o755,\'executable\':True},\n                        \'uvx\':{\'requested_path\':\'/bin/uvx\',\'resolved_path\':\'/usr/bin/uvx\',\'aliases\':[\'/bin/uvx\',\'/usr/bin/uvx\'],\n                               \'sha256\':\'b\'*64,\'bytes\':3000,\'mode\':0o755,\'executable\':True},\n                        \'node\':{\'applicability\':\'ABSENT\',\'metadata\':[],\'runtime_paths\':[]}},\n             \'inputs\':{\'no_dev\':True,\'pyproject_b64\':b64(project),\'selected_extras\':[],\'uv_lock_b64\':b64(lock)},\n             \'final\':{\'archive_unchanged\':True,\'cancelled\':False,\'containers_removed\':True,\'image_unchanged\':True,\n                      \'owned_cli_drain\':True,\'owned_image_removed\':True,\'private_context_removed\':True,\'source_unchanged\':True,\'uncertain\':False},\n             \'error_codes\':[]}\n        r = {\'SchemaVersion\':2,\'Metadata\':{\'ImageID\':image,\'OS\':{\'Family\':\'debian\',\'Name\':\'13.1\'}},\n             \'Results\':[{\'Target\':\'synthetic Debian 13\',\'Class\':\'os-pkgs\',\'Type\':\'debian\',\'Packages\':[{\'Name\':\'libc6\',\'Version\':\'2.41-1\'}]},\n                        {\'Target\':\'Python\',\'Class\':\'lang-pkgs\',\'Type\':\'python-pkg\',\'Packages\':[{\'Name\':\'alpha\',\'Version\':\'1.2.0\'},{\'Name\':\'beta\',\'Version\':\'2.0.0\'},{\'Name\':\'global-tool\',\'Version\':\'25.0\'}]},\n                        {\'Target\':\'usr/bin/uv\',\'Class\':\'lang-pkgs\',\'Type\':\'rustbinary\',\'Packages\':[{\'Name\':\'uv\',\'Version\':\'0.12.8\'},{\'Name\':\'serde\',\'Version\':\'1.0.228\'}]},\n                        {\'Target\':\'/usr/bin/uvx\',\'Class\':\'lang-pkgs\',\'Type\':\'rustbinary\',\'Packages\':[{\'Name\':\'uvx\',\'Version\':\'0.12.8\'},{\'Name\':\'tokio\',\'Version\':\'1.47.0\'},{\'Name\':\'serde\',\'Version\':\'1.0.228\'}]}]}\n        v = {\'Version\':\'0.57.1\',\'VulnerabilityDB\':{\'Version\':2,\'UpdatedAt\':\'2026-10-29T00:00:00Z\',\n                                                \'DownloadedAt\':\'2026-10-29T12:00:30Z\',\'NextUpdate\':\'2026-10-30T00:00:00Z\'}}\n        return e,r,v\n    def result(data, expect, report_override=None, version_override=None):\n        nonlocal count,passed\n        e,r,v = data\n        rr = sr_canonical(r) if report_override is None else report_override\n        vv = sr_canonical(v) if version_override is None else version_override\n        out = validate_scan_evidence(e,rr,vv); check = validate_safe_summary(sr_canonical(out))\n        count += 1\n        if not (check[\'valid\'] is True and check[\'report\'] == out and out[\'status\'] == expect):\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        passed += 1\n        return out\n    def set_at(obj,path,value):\n        node = obj\n        for key in path[:-1]: node = node[key]\n        node[path[-1]] = copy.deepcopy(value)\n    def repack_input(e,key,raw):\n        path = SR_LOCK if key == \'uv_lock_b64\' else SR_PROJECT\n        e[\'inputs\'][key] = b64(raw); e[\'source\'][\'before\'][path] = {\'sha256\':sr_digest(raw),\'bytes\':len(raw)}\n        e[\'source\'][\'after\'] = copy.deepcopy(e[\'source\'][\'before\']); e[\'source\'][\'context_sha256\'] = sr_digest(sr_canonical(e[\'source\'][\'before\']))\n    def add_node(e,r):\n        e[\'witness\'][\'node\'] = {\'applicability\':\'PRESENT\',\'runtime_paths\':[\'/usr/bin/node\'],\n            \'metadata\':[member(\'/usr/local/lib/node_modules/demo/package.json\',b\'{"name":"demo","version":"1.2.3"}\')]}\n        r[\'Results\'].append({\'Target\':\'usr/local/lib/node_modules/demo/package.json\',\'Class\':\'lang-pkgs\',\'Type\':\'node-pkg\',\'Packages\':[{\'Name\':\'demo\',\'Version\':\'1.2.3\'}]})\n    def add_finding(e,r):\n        e[\'scanner\'][\'scan_exit\'] = 1\n        r[\'Results\'][0][\'Vulnerabilities\'] = [{\'VulnerabilityID\':\'CVE-2026-12345\',\'PkgName\':\'libc6\',\'InstalledVersion\':\'2.41-1\',\n                                            \'FixedVersion\':\'\',\'Severity\':\'HIGH\',\'Status\':\'will_not_fix\'}]\n    # Every positive is a separate synthetic fixture, never a claim about an SDK.\n    result(fixture(),\'PASS\')\n    data = fixture(); data[1][\'Metadata\'][\'OS\'][\'EOSL\'] = False; result(data,\'PASS\')\n    data = fixture(); data[1][\'Results\'][1][\'Target\'] = \'actual-metadata-target-can-vary\'; result(data,\'PASS\')\n    data = fixture(); data[1][\'Results\'][2][\'Target\'] = \'/bin/uv\'; result(data,\'PASS\')\n    data = fixture(); data[0][\'build\'][\'uv\'].update(index_digest=None,index_sha256=None,material_digest=data[0][\'build\'][\'uv\'][\'platform_manifest_digest\']); result(data,\'PASS\')\n    data = fixture(); add_node(data[0],data[1]); result(data,\'PASS\')\n    data = fixture(); raw = base64.b64decode(data[0][\'inputs\'][\'uv_lock_b64\']).replace(b\'revision = 3\',b\'revision = 5\')\n    repack_input(data[0],\'uv_lock_b64\',raw); result(data,\'PASS\')\n    data = fixture(); row = data[0][\'witness\'][\'python\'][\'metadata\'][2]\n    raw = base64.b64decode(row[\'data_b64\']).replace(b\'Name: global-tool\',b\'Name: global_tool\')\n    row.update(data_b64=b64(raw),sha256=sr_digest(raw),bytes=len(raw)); result(data,\'PASS\')\n    data = fixture(); release = b\'ID=debian\\nVERSION_ID="12"\\n\'\n    data[0][\'witness\'][\'os_release\'].update(data_b64=b64(release),sha256=sr_digest(release))\n    data[1][\'Metadata\'][\'OS\'][\'Name\'] = \'12.2\'; result(data,\'PASS\')\n    data = fixture(); raw = base64.b64decode(data[0][\'inputs\'][\'uv_lock_b64\'])\n    raw = raw.replace(b\'name = "beta"\\nversion = "2.0.0"\\nsource = {registry = "https://pypi.org/simple"}\',\n                      b\'name = "beta"\\nversion = "2.0.0"\\nsource = {registry = "https://pypi.org/simple"}\\ndependencies = [{name = "gamma"}]\')\n    raw += b\'\\n[[package]]\\nname="gamma"\\nversion="0.3.0"\\nsource={registry="https://pypi.org/simple"}\\n\'\n    repack_input(data[0],\'uv_lock_b64\',raw)\n    data[0][\'witness\'][\'python\'][\'metadata\'].append(member(SR_VENV+\'/lib/python3.11/site-packages/gamma-0.3.0.dist-info/METADATA\',b\'Name: gamma\\nVersion: 0.3.0\\n\'))\n    data[1][\'Results\'][1][\'Packages\'].append({\'Name\':\'gamma\',\'Version\':\'0.3.0\'}); result(data,\'PASS\')\n    data = fixture(); add_finding(data[0],data[1]); found = result(data,\'FINDINGS\')\n    if found[\'findings\'][0][\'fixed\'] != \'\' or found[\'findings\'][0][\'status\'] != \'will_not_fix\':\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    data = fixture(); data[0][\'error_codes\'] = [\'BUILD\']; result(data,\'ERROR\')\n    empty = validate_scan_evidence({},None,None); count += 1\n    if not (empty[\'status\'] == \'ERROR\' and validate_safe_summary(sr_canonical(empty))[\'valid\'] is True):\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    passed += 1\n    mutations = [\n        (0,[\'schemaVersion\'],True),(0,[\'source\',\'after\',\'sycope/empty.py\',\'bytes\'],False),\n        (0,[\'source\',\'context_sha256\'],\'0\'*64),(0,[\'build\',\'actual_exit\'],1),\n        (0,[\'build\',\'uv\',\'actual_build_material_join\'],False),(0,[\'build\',\'uv\',\'material_digest\'],\'sha256:\'+\'f\'*64),\n        (0,[\'build\',\'uv\',\'platform\'],\'linux/arm64\'),(0,[\'build\',\'metadata_config_image_id\'],\'sha256:\'+\'f\'*64),\n        (0,[\'archive\',\'image_id\'],\'sha256:\'+\'f\'*64),(0,[\'archive\',\'unchanged\'],False),\n        (0,[\'scanner\',\'image_id\'],\'sha256:\'+\'1\'*64),(0,[\'scanner\',\'scan_exit\'],2),\n        (0,[\'scanner\',\'scan_exit\'],1),(0,[\'scanner\',\'scan_exit\'],True),\n        (0,[\'scanner\',\'config_sha256\'],\'0\'*64),(0,[\'scanner\',\'ignore_sha256\'],\'0\'*64),\n        (0,[\'scanner\',\'empty_cache_before\'],False),(0,[\'scanner\',\'same_cache\'],False),\n        (0,[\'scanner\',\'version_after_exit\'],1),(0,[\'scanner\',\'db_download_scan_only\'],False),\n        (0,[\'witness\',\'complete\'],False),(0,[\'witness\',\'image_id\'],\'sha256:\'+\'f\'*64),\n        (0,[\'witness\',\'python\',\'version\'],\'3.12.1\'),(0,[\'witness\',\'python\',\'platform\',\'platform_machine\'],\'arm64\'),\n        (0,[\'witness\',\'python\',\'metadata\'],[]),(0,[\'witness\',\'uv\',\'executable\'],False),\n        (0,[\'witness\',\'uvx\',\'aliases\'],[\'/different/uvx\']),(0,[\'witness\',\'uv\',\'mode\'],0o777),\n        (0,[\'witness\',\'node\',\'applicability\'],\'UNKNOWN\'),(0,[\'inputs\',\'no_dev\'],False),\n        (0,[\'inputs\',\'selected_extras\'],[\'unobserved\']),(0,[\'final\',\'containers_removed\'],False),\n        (0,[\'final\',\'owned_cli_drain\'],False),(0,[\'final\',\'owned_image_removed\'],False),\n        (0,[\'final\',\'private_context_removed\'],False),(0,[\'final\',\'uncertain\'],True),\n        (0,[\'final\',\'cancelled\'],True),(0,[\'final\',\'source_unchanged\'],False),\n        (1,[\'SchemaVersion\'],2.0),(1,[\'Metadata\',\'ImageID\'],\'sha256:\'+\'f\'*64),\n        (1,[\'Metadata\',\'OS\',\'EOSL\'],True),(1,[\'Metadata\',\'OS\',\'EOSL\'],0),\n        (1,[\'Metadata\',\'OS\',\'Family\'],\'unrecognized\'),(1,[\'Results\',0,\'Packages\'],[]),\n        (1,[\'Results\',1,\'Packages\'],[]),(1,[\'Results\',1,\'Packages\',0,\'Version\'],\'9.9.9\'),\n        (1,[\'Results\',2,\'Packages\'],[]),(1,[\'Results\',3,\'Packages\'],[]),\n        (1,[\'Results\',2,\'Target\'],\'unwitnessed/bin/uv\'),(1,[\'Results\',0,\'Packages\'],{}),\n        (2,[\'Version\'],\'0.57.2\'),(2,[\'VulnerabilityDB\',\'Version\'],\'2\'),\n        (2,[\'VulnerabilityDB\',\'Version\'],2.0),(2,[\'VulnerabilityDB\',\'Version\'],True),\n        (2,[\'VulnerabilityDB\',\'UpdatedAt\'],\'0001-01-01T00:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'DownloadedAt\'],\'2026-10-28T12:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'DownloadedAt\'],\'2026-10-30T12:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'NextUpdate\'],\'not-a-time\')]\n    for which,path,value in mutations:\n        result(fixture(),\'PASS\')\n        data = fixture(); before = sr_canonical(data); set_at(data[which],path,value)\n        if sr_canonical(data) == before: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        result(data,\'ERROR\')\n    # Extra invalid data is added to an otherwise passing complete report. A\n    # permissive parser would therefore wrongly PASS, rather than reject a\n    # different missing required field and conceal the intended counterexample.\n    valid_raw = sr_canonical(fixture()[1])\n    for raw in (valid_raw[:-1]+b\',"SchemaVersion":2}\',valid_raw[:-1]+b\',"extra":NaN}\',\n                valid_raw[:-1]+b\',"extra":1e9999}\',valid_raw[:-1]+b\',"extra":"\\\\u0000"}\',\n                valid_raw[:-1]+b\',"\\\\ud800":1}\',valid_raw[:-1]+b\',"extra":"\\\\udfff"}\',valid_raw+b\'\\x80\',\n                valid_raw[:-1]+b\',"extra":\'+b\'[\'*33+b\'0\'+b\']\'*33+b\'}\'):\n        result(fixture(),\'PASS\'); result(fixture(),\'ERROR\',report_override=raw)\n    prefix = valid_raw[:-1]+b\',"extra":"\'; suffix = b\'"}\'\n    oversize = prefix+b\'x\'*(SR_RAW_MAX+1-len(prefix)-len(suffix))+suffix\n    result(fixture(),\'PASS\'); result(fixture(),\'ERROR\',report_override=oversize)\n    del oversize\n    result(fixture(),\'PASS\'); data = fixture(); raw = sr_canonical(data[2])[:-1]+b\',"Version":"0.57.1"}\'\n    result(data,\'ERROR\',version_override=raw)\n    # Test-local metadata/TOML transport is rehashed to reach semantic guards.\n    for change in (\'unknown_source\',\'marker\',\'virtual_root\',\'requirements\',\'extra_lock_record\'):\n        result(fixture(),\'PASS\'); data = fixture(); e = data[0]\n        lock = base64.b64decode(e[\'inputs\'][\'uv_lock_b64\'])\n        if change == \'unknown_source\': lock = lock.replace(b\'{registry = "https://pypi.org/simple"}\',b\'{git = "https://invalid.example/repo"}\',1)\n        elif change == \'marker\': lock = lock.replace(b\'{name = "beta"}\',b\'{name = "beta", marker = "python_version < \\\'3.0\\\'"}\',1)\n        elif change == \'virtual_root\': lock = lock.replace(b\'name = "synthetic-connector"\',b\'name = "other-connector"\')\n        elif change == \'requirements\': lock = lock.replace(b\'specifier = ">=2.0"\',b\'specifier = ">=9.0"\')\n        else: lock += b\'\\n[[package]]\\nname="unselected"\\nversion="1.0.0"\\nsource={registry="https://pypi.org/simple"}\\n\'\n        repack_input(e,\'uv_lock_b64\',lock); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); row = data[0][\'witness\'][\'python\'][\'metadata\'][0]\n    raw = base64.b64decode(row[\'data_b64\'])+b\'Name: alpha\\n\'; raw = raw.replace(b\'\\n\\nSynthetic only.\\n\',b\'\\n\')\n    row.update(data_b64=b64(raw),sha256=sr_digest(raw),bytes=len(raw)); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'python\'][\'metadata\'].pop(); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_node(data[0],data[1]); data[1][\'Results\'].pop(); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'node\'][\'applicability\'] = \'PRESENT\'; data[0][\'witness\'][\'node\'][\'runtime_paths\'] = [\'/usr/bin/node\']; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[1][\'Results\'].append({\'Target\':\'node\',\'Class\':\'lang-pkgs\',\'Type\':\'node-pkg\',\'Packages\':[{\'Name\':\'unobserved\',\'Version\':\'1.0.0\'}]}); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'uvx\'][\'aliases\'].append(\'/bin/uv\'); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[0][\'scanner\'][\'scan_exit\'] = 0; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'Severity\'] = \'LOW\'; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'PkgName\'] = {\'private\':\'never artifact this\'}; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'InstalledVersion\'] = \'999.0\'; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[0][\'final\'][\'owned_cli_drain\'] = False; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); row = data[1][\'Results\'][0][\'Vulnerabilities\'][0]\n    row[\'FixedVersion\'] = \'1\'*512; data[1][\'Results\'][0][\'Vulnerabilities\'] = [copy.deepcopy(row) for _ in range(2500)]\n    result(data,\'ERROR\')\n    # Safe summary policy is checked for both ordinary and failure projections.\n    good = result(fixture(),\'PASS\')\n    for path,value in (([\'schemaVersion\'],1.0),([\'category\'],\'/private/path\'),([\'identities\',\'unknown\'],\'secret\'),\n                       ([\'coverage\',\'python\',\'installed_pairs\'],True),([\'actual_exit\'],1),([\'cleanup\'],False),\n                       ([\'db\',\'next_update\'],\'2026-10-28T00:00:00Z\')):\n        changed = copy.deepcopy(good); set_at(changed,path,value); count += 1\n        if validate_safe_summary(sr_canonical(changed)) != {\'valid\':False,\'report\':None}:\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        passed += 1\n    bad_error = sr_empty_summary(); bad_error[\'findings\'] = [{\'id\':\'CVE-1\',\'pkg\':{\'raw\':\'never\'},\'installed\':\'1\',\'fixed\':\'\',\'severity\':\'HIGH\',\'status\':None}]\n    count += 1\n    if validate_safe_summary(sr_canonical(bad_error)) != {\'valid\':False,\'report\':None}:\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    passed += 1\n    return {\'status\':\'C04_REDUCER_DATA_CONTROLS_PASSED\',\'case_count\':count,\'passed\':passed,\'failed\':0}\n\n\ndef run_data_controls():\n    """Expose fixed failure text for all ordinary synthetic-control failures."""\n    try:\n        return sr_data_controls()\n    except Exception:\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\') from None\n'
REDUCER = {'__name__':'c04_passive_scan_reducer'}
exec(compile(REDUCER_SOURCE,'<inline-c04-reducer>','exec'), REDUCER)

MAX_ARCHIVE = 4 * 1024 * 1024 * 1024
MAX_HOST_TOOL = 128 * 1048576
CANCELLED = False
UNCERTAIN = False
ENV = None
INTENTS = []
END = None
WORK_END = None
DOCKER = None
UID = None
GID = None
PHASE = 'BOOTSTRAP'


class Failure(Exception):
    def __init__(self, code):
        self.code = code


def need(ok, code):
    if not ok:
        raise Failure(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def interrupted(_number, _frame):
    global CANCELLED
    CANCELLED = True


def expired(_number, _frame):
    # An unsafe terminal cutoff cannot publish a normal successful outcome.
    os._exit(2)


def work_check(cleanup=False):
    need(time.monotonic() < (END if cleanup else WORK_END) and (cleanup or not CANCELLED), 'CANCELLED')


def info_identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink, 'bytes': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def file_identity(path):
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         info.st_uid == UID and stat.S_IMODE(info.st_mode) == 0o600, 'ARCHIVE')
    return info_identity(info)


def read_file(path, cap, *, empty=False, owned=True):
    need(path.resolve(strict=True) == path, 'SOURCE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and (not owned or first.st_uid == UID) and
             0 <= first.st_size <= cap and (empty or first.st_size > 0), 'SOURCE')
        chunks = bytearray()
        while True:
            part = os.read(fd, min(1048576, cap + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
            need(len(chunks) <= cap, 'OVERFLOW')
            work_check()
        last = os.fstat(fd)
        fields = lambda x: (x.st_dev, x.st_ino, x.st_mode, x.st_uid, x.st_gid, x.st_nlink,
                            x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        need(fields(first) == fields(last) == fields(path.lstat()) and len(chunks) == first.st_size,
             'SOURCE')
        return bytes(chunks)
    finally:
        os.close(fd)


def hash_file(path, cap):
    before = file_identity(path)
    need(0 < before['bytes'] <= cap, 'ARCHIVE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need(info_identity(os.fstat(fd)) == before, 'ARCHIVE')
        sha = hashlib.sha256()
        count = 0
        while True:
            part = os.read(fd, 1048576)
            if not part:
                break
            count += len(part)
            need(count <= cap, 'OVERFLOW')
            sha.update(part)
            work_check()
        need(count == before['bytes'] and info_identity(os.fstat(fd)) == before and file_identity(path) == before, 'ARCHIVE')
        return sha.hexdigest()
    finally:
        os.close(fd)


def owner_json(raw, cap=2097152):
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'JSON')
            result[key] = value
        return result
    def constant(_value):
        raise Failure('JSON')
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
        def visit(value, depth=0):
            need(depth <= 32, 'JSON')
            if type(value) is str:
                need('\0' not in value and not any(0xD800 <= ord(c) <= 0xDFFF for c in value), 'JSON')
            elif type(value) is dict:
                for key, item in value.items():
                    visit(key, depth + 1)
                    visit(item, depth + 1)
            elif type(value) is list:
                for item in value:
                    visit(item, depth + 1)
            elif type(value) is float:
                need(math.isfinite(value), 'JSON')
            else:
                need(value is None or type(value) in (bool, int), 'JSON')
        visit(obj)
        return obj
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise Failure('JSON') from None


def cli(argv, seconds=30, *, cleanup=False, stdout_cap=1048576, allow_exit=False):
    work_check(cleanup)
    remaining = (END if cleanup else WORK_END) - time.monotonic() - 7
    need(remaining > 0, 'CANCELLED')
    args = [DOCKER, *argv[1:]] if argv[0] == 'docker' else argv
    code, out, err, elapsed = capture(args, min(seconds, remaining, 1200), cleanup=cleanup,
                                     stdout_cap=stdout_cap, stderr_cap=2097152)
    need(type(code) is int and (allow_exit or code == 0), 'EXIT')
    return (code, out, err, elapsed) if allow_exit else out


def inspect_container(cid, cleanup=False):
    rows = owner_json(cli(['docker', 'inspect', cid], cleanup=cleanup))
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'SCANNER')
    return rows[0]


def recover(intent):
    raw = cli(['docker', 'ps', '--all', '--no-trunc', '--filter',
               'label=org.trueid.c04.owner=' + intent['owner'], '--format', '{{.ID}}'], cleanup=True)
    ids = raw.decode('ascii').splitlines()
    need(len(ids) <= 1 and all(re.fullmatch('[0-9a-f]{64}', cid) is not None for cid in ids), 'CLEANUP')
    for cid in ids:
        row = inspect_container(cid, True)
        need(row['Id'] == cid and row['Name'] == '/' + intent['name'] and row['Image'] == intent['image'] and
             row['Config']['Labels'].get('org.trueid.c04.owner') == intent['owner'], 'CLEANUP')
    return ids


def retire(intent):
    global UNCERTAIN
    if intent['closed']:
        return
    try:
        for cid in recover(intent):
            row = inspect_container(cid, True)
            if row['State']['Running']:
                cli(['docker', 'stop', '--signal', 'SIGTERM', '--timeout', '20', cid], 30,
                    cleanup=True, allow_exit=True)
                row = inspect_container(cid, True)
                if row['State']['Running']:
                    cli(['docker', 'kill', '--signal', 'SIGKILL', cid], cleanup=True)
                    row = inspect_container(cid, True)
            need(row['State']['Running'] is False and row['State']['Pid'] == 0, 'CLEANUP')
            cli(['docker', 'rm', '--volumes', cid], cleanup=True)
        need(recover(intent) == [], 'CLEANUP')
        intent['closed'] = True
        if not intent['acked']:
            UNCERTAIN = True
    except BaseException:
        UNCERTAIN = True
        raise


def create_container(image, argv, mounts, *, network='none', witness=False):
    need(re.fullmatch('sha256:[0-9a-f]{64}', image) is not None and network in ('none', 'bridge'), 'SCANNER')
    owner = secrets.token_hex(16)
    intent = {'owner': owner, 'name': 'trueid-c04-' + owner, 'image': image, 'acked': False, 'closed': False}
    INTENTS.append(intent)  # The exact recovery capability exists before Docker can create a resource.
    environment = ['-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp', 'TMPDIR=/tmp',
                   'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1', *argv]
    entrypoint = '/bin/true' if witness else '/usr/bin/env'
    command = ['trueid-never-started-witness'] if witness else environment
    config = ['docker', 'create', '--name', intent['name'], '--label', 'org.trueid.c04.owner=' + owner,
              '--platform', 'linux/amd64', '--init', '--user', str(UID) + ':' + str(GID), '--log-driver', 'none',
              '--read-only', '--network', network, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '--pids-limit', '256', '--cpus', '2', '--memory', '3g', '--memory-swap', '3g',
              '--stop-signal', 'SIGTERM', '--stop-timeout', '20', '--workdir', '/tmp',
              '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=256m,uid=' + str(UID) + ',gid=' + str(GID) + ',mode=0700']
    for source, target, readonly in mounts:
        need(source.resolve(strict=True) == source and source.is_dir() and
             target in ('/input', '/control', '/cache') and type(readonly) is bool, 'SCANNER')
        config += ['--mount', 'type=bind,source=' + str(source) + ',target=' + target +
                   (',readonly' if readonly else '')]
    cid = cli(config + ['--entrypoint', entrypoint, image] + command).decode('ascii').strip()
    intent['acked'] = True
    need(re.fullmatch('[0-9a-f]{64}', cid) is not None and recover(intent) == [cid], 'SCANNER')
    row = inspect_container(cid)
    binds = [item for item in row['Mounts'] if item['Type'] == 'bind']
    expected = sorted((target, str(source), not readonly) for source, target, readonly in mounts)
    actual = sorted((item['Destination'], item['Source'], item['RW']) for item in binds)
    need(row['Config']['User'] == str(UID) + ':' + str(GID) and
         row['Config']['Entrypoint'] == [entrypoint] and row['Config']['Cmd'] == command and
         row['Config']['Tty'] is False and actual == expected and
         row['HostConfig']['ReadonlyRootfs'] is True and row['HostConfig']['NetworkMode'] == network and
         sorted(row['HostConfig']['CapDrop']) == ['ALL'] and
         row['HostConfig']['Privileged'] is False and not row['HostConfig'].get('CapAdd') and
         not row['HostConfig'].get('GroupAdd') and row['HostConfig'].get('PidMode', '') == '' and
         'no-new-privileges' in (row['HostConfig'].get('SecurityOpt') or []) and
         all(item['Type'] in ('bind', 'tmpfs') for item in row['Mounts']) and
         row['State']['Running'] is False and row['State']['Pid'] == 0,
         'SCANNER')
    return intent, cid


def scanner(image, args, mounts, *, seconds=120, network='none', scan=False):
    intent = None
    try:
        intent, cid = create_container(image, ['/usr/local/bin/trivy', *args], mounts, network=network)
        code, raw, stderr, elapsed = cli(['docker', 'start', '--attach', cid], seconds,
            stdout_cap=64 * 1048576 if scan else 1048576, allow_exit=True)
        row = inspect_container(cid)
        need(row['Image'] == image and row['State']['Running'] is False and row['State']['Pid'] == 0 and
             row['State']['OOMKilled'] is False and row['State'].get('Error', '') == '' and
             type(row['State']['ExitCode']) is int and row['State']['ExitCode'] == code and 0 <= code <= 255,
             'SCANNER')
        return code, raw, stderr, elapsed
    finally:
        if intent is not None:
            retire(intent)


def capture(argv, seconds, *, cleanup=False, stdout_cap=1048576, stderr_cap=65536):
    """Bound one CLI and its causally owned children; never reap the anchor early."""
    import ctypes
    import errno
    import math
    global UNCERTAIN
    process = main_ref = self_ref = terminal = None
    refs = {}
    selector = selectors.DefaultSelector()
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    started = time.monotonic()
    problem = None
    clean = False
    armed = False
    previous = None
    libc = None
    active_before = getattr(capture, '_active', False)

    def no_children():
        try: os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError: return True
        return False

    def row(dfd):
        fd = os.open('stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=dfd)
        try: data = os.read(fd, 8193)
        finally: os.close(fd)
        need(len(data) <= 8192 and b')' in data, 'OWNED_STAT')
        fields = data[data.rfind(b')') + 2:].split()
        need(len(fields) >= 20, 'OWNED_STAT')
        return {'pid': int(data[:data.index(b' ')]), 'ppid': int(fields[1]),
                'start': int(fields[19])}

    def read(ref):
        try: current = row(ref['proc'])
        except OSError as error:
            if error.errno in (errno.ENOENT, errno.ESRCH): return None
            raise
        need((current['pid'], current['start']) == ref['identity'], 'OWNED_IDENTITY')
        return current

    def close_ref(ref):
        for key in ('pidfd', 'proc'):
            fd = ref[key]
            if fd is not None:
                os.close(fd)
                ref[key] = None

    def pin(pid, parent=None):
        parent_before = read(parent) if parent is not None else None
        need(parent is None or parent_before is not None, 'OWNED_RESCAN')
        dfd = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        pfd = None
        try:
            first = row(dfd)
            pfd = os.pidfd_open(pid, 0)
            last = row(dfd)
            need(first['pid'] == last['pid'] == pid and first['start'] == last['start'], 'OWNED_RESCAN')
            if parent is not None:
                parent_after = read(parent)
                need(parent_after is not None and first['ppid'] == last['ppid'] == parent_before['pid'] ==
                     parent_after['pid'], 'OWNED_RESCAN')
            return {'proc': dfd, 'pidfd': pfd, 'identity': (pid, last['start'])}
        except BaseException:
            if pfd is not None: os.close(pfd)
            os.close(dfd)
            raise

    def exited(ref):
        # WNOWAIT is also the identity-safe readiness observation for an adopted child.
        poller = selectors.DefaultSelector()
        try:
            poller.register(ref['pidfd'], selectors.EVENT_READ)
            return bool(poller.select(0))
        finally: poller.close()

    def discover():
        nonlocal main_ref
        ids = sorted(int(value) for value in os.listdir('/proc') if value.isdecimal())
        need(len(ids) <= 4096, 'OWNED_SCAN_CAP')
        parents = {os.getpid(): self_ref}
        for ref in refs.values():
            if read(ref) is not None: parents[ref['identity'][0]] = ref
        known = {ref['identity'][0] for ref in refs.values()}
        for pid in ids:
            if pid == os.getpid() or pid in known: continue
            dfd = None
            try:
                dfd = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                candidate = row(dfd)
                parent = parents.get(candidate['ppid'])
                if parent is None: continue
                ref = pin(pid, parent)
            except OSError as error:
                if error.errno in (errno.ENOENT, errno.ESRCH): continue
                raise
            except Failure as error:
                if error.code == 'OWNED_RESCAN': continue
                raise
            finally:
                if dfd is not None: os.close(dfd)
            if len(refs) >= 256:
                close_ref(ref)
                raise Failure('OWNED_PROCESS_CAP')
            refs[ref['identity']] = ref
            parents[pid] = ref
            known.add(pid)
            if process is not None and pid == process.pid and main_ref is None: main_ref = ref

    def observe():
        nonlocal terminal
        if main_ref is not None and terminal is None:
            terminal = os.waitid(os.P_PIDFD, main_ref['pidfd'], os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if terminal is not None:
                need(terminal.si_pid == process.pid and terminal.si_code in
                     (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED), 'OWNED_MAIN_STATUS')
        for identity, ref in list(refs.items()):
            if ref is main_ref or not exited(ref): continue
            try:
                result = os.waitid(os.P_PIDFD, ref['pidfd'], os.WEXITED | os.WNOHANG)
                need(result is None or result.si_pid == identity[0], 'OWNED_REAP_IDENTITY')
            except ChildProcessError:
                pass  # Its owned living parent reaped it, or it is not adopted yet.
            close_ref(ref)
            del refs[identity]

    def pump(discard=False):
        for key, _mask in selector.select(0.02):
            try: part = os.read(key.fd, 65536)
            except BlockingIOError: continue
            if not part:
                selector.unregister(key.fileobj)
                continue
            if not discard:
                target = chunks[key.data]
                limit = stdout_cap if key.data == 'stdout' else stderr_cap
                room = max(0, limit - len(target))
                target.extend(part[:room])
                need(len(part) <= room, 'CAPTURE_CAP')

    def finish():
        nonlocal clean
        if selector.get_map(): return False
        if process is None:
            clean = not refs and no_children()
            return clean
        if main_ref is None or terminal is None or any(ref is not main_ref for ref in refs.values()): return False
        # Single-thread/no-concurrent-spawn lease makes every other direct child
        # causally owned; an unseen adopted root must be discovered before reap.
        fd = os.open('/proc/self/task/' + str(os.getpid()) + '/children', os.O_RDONLY | os.O_CLOEXEC)
        try: children = os.read(fd, 65537)
        finally: os.close(fd)
        need(len(children) <= 65536, 'OWNED_CHILDREN_CAP')
        if {int(value) for value in children.split()} != {process.pid}: return False
        expected = terminal.si_status if terminal.si_code == os.CLD_EXITED else -terminal.si_status
        actual = process.wait(timeout=0)  # Sole exact reaper, after descendants and PIPE EOF.
        need(actual == expected, 'OWNED_MAIN_REAP_STATUS')
        close_ref(main_ref)
        del refs[main_ref['identity']]
        clean = no_children()
        need(clean, 'OWNED_DRAIN_UNPROVEN')
        return True

    try:
        need(cleanup or not CANCELLED, 'CANCELLED')
        need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 1200 and
             type(stdout_cap) is type(stderr_cap) is int and 0 < stdout_cap <= 67108864 and
             0 < stderr_cap <= 2097152, 'CAPTURE_BOUNDS')
        need(not active_before and len(os.listdir('/proc/self/task')) == 1 and
             signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and no_children(), 'OWNED_CAPTURE_PREFLIGHT')
        capture._active = True
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        value = ctypes.c_int(-1)
        need(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value in (0, 1), 'OWNED_GET_SUBREAPER')
        previous = value.value
        need(libc.prctl(36, 1, 0, 0, 0) == 0, 'OWNED_SET_SUBREAPER')
        armed = True
        need(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == 1, 'OWNED_VERIFY_SUBREAPER')
        self_ref = pin(os.getpid())
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, env=ENV)
        main_ref = pin(process.pid, self_ref)
        refs[main_ref['identity']] = main_ref
        for label in chunks:
            pipe = getattr(process, label)
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        while True:
            need(cleanup or not CANCELLED, 'CANCELLED')
            need(time.monotonic() - started < seconds, 'TIMEOUT')
            discover()
            observe()
            pump()
            if finish(): break
    except BaseException as error:
        UNCERTAIN = True  # Preserve R2 policy: every capture exception poisons later stages.
        problem = error
    finally:
        if armed and not clean:
            until = time.monotonic() + 6
            term_until = time.monotonic() + 3
            sent = set()
            while time.monotonic() < until:
                try:
                    if self_ref is not None: discover()
                except BaseException:
                    UNCERTAIN = True
                try:
                    observe()
                except BaseException:
                    UNCERTAIN = True
                signum = signal.SIGTERM if time.monotonic() < term_until else signal.SIGKILL
                # Failed discovery or one damaged ref never suppresses other proved pidfds.
                for identity, ref in list(refs.items()):
                    try:
                        if (identity, signum) in sent or exited(ref): continue
                        signal.pidfd_send_signal(ref['pidfd'], signum, None, 0)
                        sent.add((identity, signum))
                    except ProcessLookupError: pass
                    except BaseException: UNCERTAIN = True  # No numeric/global fallback.
                try:
                    pump(discard=True)
                except BaseException:
                    UNCERTAIN = True
                try:
                    if finish(): break
                except BaseException:
                    UNCERTAIN = True
                time.sleep(0.01)
        if armed and clean:
            try:
                value = ctypes.c_int(-1)
                need(libc.prctl(36, previous, 0, 0, 0) == 0 and
                     libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == previous,
                     'OWNED_RESTORE_SUBREAPER')
            except BaseException as error:
                UNCERTAIN = True
                problem = problem or error
        if armed and not clean:
            UNCERTAIN = True
            problem = problem or Failure('OWNED_DRAIN_UNPROVEN')
        for ref in list(refs.values()) + ([self_ref] if self_ref is not None else []):
            try: close_ref(ref)
            except BaseException as error:
                UNCERTAIN = True
                problem = problem or error
        try:
            selector.close()
            if process is not None:
                process.stdout.close()
                process.stderr.close()
        except BaseException as error:
            UNCERTAIN = True
            problem = problem or error
        if not active_before: capture._active = False
    if problem is not None: raise problem
    need(clean, 'OWNED_DRAIN_UNPROVEN')
    return process.returncode, bytes(chunks['stdout']), bytes(chunks['stderr']), round(time.monotonic() - started, 3)


def write_new(path, raw, mode=0o600):
    need(type(raw) is bytes, 'INTERNAL')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        count = 0
        while count < len(raw):
            actual = os.write(fd, raw[count:])
            need(actual > 0, 'INTERNAL')
            count += actual
            work_check(True)
        os.fsync(fd)
        need(os.fstat(fd).st_size == len(raw), 'INTERNAL')
    finally:
        os.close(fd)


def source_context(checkout, context):
    need(checkout.resolve(strict=True) == checkout and checkout.is_dir() and context.resolve() == context,
         'SOURCE')
    head = cli(['/usr/bin/git', '-C', str(checkout), 'rev-parse', 'HEAD']).decode('ascii').strip()
    need(re.fullmatch('[0-9a-f]{40}', head) is not None and head == os.environ['GITHUB_SHA'], 'SOURCE')
    raw_names = cli(['/usr/bin/git', '-C', str(checkout), 'ls-files', '-z', '--',
                     'sycope', 'integrations/sycope', '.dockerignore'])
    names = raw_names.decode('utf-8').split('\0')
    need(names[-1] == '' and len(names) > 4, 'SOURCE')
    names = names[:-1]
    need(len(names) == len(set(names)) and len(names) <= 4096, 'SOURCE')
    allowed = set(names)
    for directory in ('sycope', 'integrations/sycope'):
        parent = checkout / directory
        need(parent.resolve(strict=True) == parent and parent.is_dir(), 'SOURCE')
        observed = set()
        for current, dirs, files in os.walk(parent, followlinks=False):
            for item in dirs:
                child = Path(current) / item
                need(not child.is_symlink(), 'SOURCE')
            for item in files:
                child = Path(current) / item
                need(not child.is_symlink(), 'SOURCE')
                observed.add(child.relative_to(checkout).as_posix())
            work_check()
        need(observed == {name for name in allowed if name.startswith(directory + '/')}, 'SOURCE')
    result = {}
    total = 0
    context.mkdir(mode=0o700)
    for name in sorted(names):
        pieces = name.split('/')
        need(not name.startswith('/') and '..' not in pieces and
             (name == '.dockerignore' or name.startswith(('sycope/', 'integrations/sycope/'))) and
             not any(part in ('.git', '.venv', '.env', 'backups', '__pycache__') for part in pieces) and
             not name.endswith(('.db', '.pyc', '.pyo')) and '\n' not in name and '\r' not in name,
             'SOURCE')
        raw = read_file(checkout / name, 16 * 1048576, empty=True)
        total += len(raw)
        need(total <= 128 * 1048576, 'SOURCE')
        target = context / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(target, raw, 0o400)
        result[name] = {'sha256': digest(raw), 'bytes': len(raw)}
    required = {'integrations/sycope/Dockerfile', 'integrations/sycope/pyproject.toml',
                'integrations/sycope/uv.lock', 'integrations/sycope/.python-version', '.dockerignore'}
    need(required <= set(result), 'SOURCE')
    dockerfile = read_file(context / 'integrations/sycope/Dockerfile', 1048576).decode('utf-8')
    need('COPY --from=ghcr.io/astral-sh/uv:0.12.8 /uv /uvx /bin/' in dockerfile and
         'RUN cd integrations/sycope && uv sync --frozen --no-dev --compile-bytecode' in dockerfile and
         re.search(r'^FROM python:3\.11-slim@sha256:[0-9a-f]{64}$', dockerfile, re.M) is not None and
         'COPY sycope/ /app/sycope/' in dockerfile and
         'COPY integrations/sycope/ /app/integrations/sycope/' in dockerfile, 'SOURCE')
    need(read_file(context / '.dockerignore', 1048576, empty=True) ==
         b'target/\n.git/\n.env\n*.db\ndata/\n!data/oui.csv\n.devcontainer/\nbackups/\n', 'SOURCE')
    return head, result


def recheck_source(checkout, before):
    result = {}
    for name in sorted(before):
        raw = read_file(checkout / name, 16 * 1048576, empty=True)
        result[name] = {'sha256': digest(raw), 'bytes': len(raw)}
    names = cli(['/usr/bin/git', '-C', str(checkout), 'ls-files', '-z', '--',
                 'sycope', 'integrations/sycope', '.dockerignore']).decode('utf-8').split('\0')
    need(names[-1] == '' and set(names[:-1]) == set(before), 'SOURCE')
    observed = set()
    for directory in ('sycope', 'integrations/sycope'):
        for current, dirs, files in os.walk(checkout / directory, followlinks=False):
            need(all(not (Path(current) / name).is_symlink() for name in dirs + files), 'SOURCE')
            observed.update((Path(current) / name).relative_to(checkout).as_posix() for name in files)
            work_check()
    need(observed | {'.dockerignore'} == set(before), 'SOURCE')
    need(canonical(result) == canonical(before), 'SOURCE')
    return result


def image_info(reference):
    rows = owner_json(cli(['docker', 'image', 'inspect', reference]))
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, 'BUILD')
    row = rows[0]
    need(type(row['Id']) is str and re.fullmatch('sha256:[0-9a-f]{64}', row['Id']) is not None and
         row['Os'] == 'linux' and row['Architecture'] == 'amd64' and not row['Config'].get('Volumes'), 'BUILD')
    return row


def archive_image(path, image):
    before = file_identity(path)
    archive_sha = hash_file(path, MAX_ARCHIVE)
    with path.open('rb') as stream:
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            members = {}
            for member in tar:
                need(len(members) < 200000 and type(member.name) is str and not member.name.startswith('/') and
                     '..' not in member.name.split('/') and member.name not in members and
                     (member.isfile() or member.isdir()), 'ARCHIVE')
                members[member.name] = member
            need('manifest.json' in members and members['manifest.json'].isfile() and
                 0 < members['manifest.json'].size <= 1048576, 'ARCHIVE')
            with tar.extractfile(members['manifest.json']) as source:
                manifest = owner_json(source.read(1048577), 1048576)
            need(type(manifest) is list and len(manifest) == 1 and type(manifest[0]) is dict and
                 type(manifest[0].get('Config')) is str and type(manifest[0].get('Layers')) is list and
                 manifest[0]['Layers'], 'ARCHIVE')
            config_name = manifest[0]['Config']
            need(config_name in members and members[config_name].isfile() and
                 0 < members[config_name].size <= 4194304, 'ARCHIVE')
            with tar.extractfile(members[config_name]) as source:
                config = source.read(4194305)
            need('sha256:' + digest(config) == image, 'ARCHIVE')
            for name in manifest[0]['Layers']:
                need(type(name) is str and name in members and members[name].isfile(), 'ARCHIVE')
    need(file_identity(path) == before and hash_file(path, MAX_ARCHIVE) == archive_sha, 'ARCHIVE')
    return {'sha256': archive_sha, 'bytes': before['bytes'], 'image_id': image, 'unchanged': False}


def material_uri(uri):
    need(type(uri) is str and 0 < len(uri) <= 2048 and uri.startswith('pkg:docker/'), 'LINEAGE')
    encoded = uri[len('pkg:docker/'):]
    path, separator, query = encoded.partition('?')
    need('#' not in path and path.count('@') == 1, 'LINEAGE')
    name, version = path.rsplit('@', 1)
    name, version = urllib.parse.unquote(name), urllib.parse.unquote(version)
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True) if separator else []
    need(len(pairs) == len({key for key, _value in pairs}), 'LINEAGE')
    qualifiers = dict(pairs)
    platform = qualifiers.get('platform')
    need(platform == 'linux/amd64' and set(qualifiers) <= {'platform', 'repository_url'}, 'LINEAGE')
    repository = qualifiers.get('repository_url', '')
    if repository:
        repository = repository.removeprefix('https://').rstrip('/')
        full = repository + '/' + name
    else:
        full = name
    return full, version, platform


def exact_manifest_bytes(raw, expected):
    # Authenticate original registry JSON bytes, never JSON-reserialize a digest.
    candidates = [raw]
    if raw.endswith(b'\n'):
        candidates.append(raw[:-1])
    matching = [value for value in candidates if 'sha256:' + digest(value) == expected]
    need(len(matching) == 1, 'LINEAGE')
    return matching[0]


def build_lineage(metadata_raw, sdk_id):
    meta = owner_json(metadata_raw, 4194304)
    need(type(meta) is dict and meta.get('containerimage.config.digest') == sdk_id, 'LINEAGE')
    keys = [key for key in meta if key == 'buildx.build.provenance' or
            key == 'buildx.build.provenance/linux/amd64']
    need(len(keys) == 1 and type(meta[keys[0]]) is dict, 'LINEAGE')
    provenance = meta[keys[0]]
    need(type(provenance.get('materials')) is list and provenance['materials'], 'LINEAGE')
    selected = []
    for row in provenance['materials']:
        need(type(row) is dict and type(row.get('uri')) is str and type(row.get('digest')) is dict, 'LINEAGE')
        if row['uri'].startswith('pkg:docker/'):
            try:
                name, version, platform = material_uri(row['uri'])
            except Failure:
                if 'astral-sh' in row['uri'] or '/uv@' in row['uri']:
                    raise
                continue
            if name == 'ghcr.io/astral-sh/uv':
                need(version == '0.12.8' and platform == 'linux/amd64' and
                     set(row['digest']) == {'sha256'} and
                     re.fullmatch('[0-9a-f]{64}', row['digest']['sha256']) is not None, 'LINEAGE')
                selected.append(row)
    need(len(selected) == 1, 'LINEAGE')
    material = selected[0]
    material_digest = 'sha256:' + material['digest']['sha256']
    reference = 'ghcr.io/astral-sh/uv@' + material_digest
    raw = cli(['docker', 'buildx', 'imagetools', 'inspect', '--raw', reference], 120, stdout_cap=2097152)
    raw = exact_manifest_bytes(raw, material_digest)
    record = owner_json(raw)
    need(type(record) is dict and type(record.get('schemaVersion')) is int and record['schemaVersion'] == 2 and type(record.get('mediaType')) is str,
         'LINEAGE')
    index_digest = index_sha = None
    if record['mediaType'] in ('application/vnd.oci.image.index.v1+json',
                               'application/vnd.docker.distribution.manifest.list.v2+json'):
        need(type(record.get('manifests')) is list, 'LINEAGE')
        matching = [row for row in record['manifests'] if type(row) is dict and type(row.get('platform')) is dict and
                    row['platform'].get('os') == 'linux' and row['platform'].get('architecture') == 'amd64' and
                    row['platform'].get('variant', '') in ('', 'v1')]
        need(len(matching) == 1 and type(matching[0].get('digest')) is str and
             re.fullmatch('sha256:[0-9a-f]{64}', matching[0]['digest']) is not None and
             matching[0]['mediaType'] in ('application/vnd.oci.image.manifest.v1+json',
                                        'application/vnd.docker.distribution.manifest.v2+json'), 'LINEAGE')
        index_digest, index_sha = material_digest, digest(raw)
        chosen = matching[0]['digest']
        raw = cli(['docker', 'buildx', 'imagetools', 'inspect', '--raw',
                   'ghcr.io/astral-sh/uv@' + chosen], 120, stdout_cap=2097152)
        raw = exact_manifest_bytes(raw, chosen)
        record = owner_json(raw)
    else:
        chosen = material_digest
    need(type(record.get('schemaVersion')) is int and record['schemaVersion'] == 2 and record.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json',
                                    'application/vnd.docker.distribution.manifest.v2+json') and
         type(record.get('config')) is dict and type(record.get('layers')) is list and record['layers'] and
         re.fullmatch('sha256:[0-9a-f]{64}', record['config'].get('digest', '')) is not None, 'LINEAGE')
    return {'reference': 'ghcr.io/astral-sh/uv:0.12.8', 'material_uri': material['uri'],
            'material_digest': material_digest, 'index_digest': index_digest,
            'platform_manifest_digest': chosen, 'platform': 'linux/amd64',
            'index_sha256': index_sha, 'manifest_sha256': digest(raw), 'actual_build_material_join': True}


def inspect_rootfs(path, image_id, image_info):
    """Inspect one complete never-started SDK export as data; never extract or execute it."""
    need(image_info['Os'] == 'linux' and image_info['Architecture'] == 'amd64', 'WITNESS')
    before = file_identity(path)
    need(0 < before['bytes'] <= MAX_ARCHIVE and before['bytes'] % 512 == 0, 'WITNESS')
    root_hash = hash_file(path, MAX_ARCHIVE)
    nodes = {}
    total_size = 0
    payload_size = 0
    emitted_payload_size = 0
    member_count = 0
    root_seen = False
    cache = {}

    def clean(name, base=()):
        need(type(name) is str and
             not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name) and
             0 < len(name.encode('utf-8')) <= 4096, 'WITNESS')
        parts = [] if name.startswith('/') else list(base)
        for item in name.split('/'):
            if item in ('', '.'):
                continue
            if item == '..':
                need(parts, 'WITNESS')
                parts.pop()
            else:
                parts.append(item)
        return '/'.join(parts)

    with path.open('rb') as stream:
        reader_before = os.fstat(stream.fileno())
        need(stat.S_ISREG(reader_before.st_mode) and info_identity(reader_before) == before, 'WITNESS')
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            for member in archive:
                work_check()
                member_count += 1
                need(member_count <= 200000 and not member.name.startswith('/') and
                     '..' not in member.name.split('/'), 'WITNESS')
                name = clean(member.name)
                if not name:
                    need(member.isdir() and not root_seen, 'WITNESS')
                    root_seen = True
                    continue
                need(name not in nodes and type(member.size) is int and 0 <= member.size <= MAX_ARCHIVE and
                     (member.isfile() or member.isdir() or member.issym() or member.islnk()) and
                     member.sparse is None, 'WITNESS')
                if member.issym() or member.islnk():
                    clean(member.linkname, () if member.islnk() else name.split('/')[:-1])
                total_size += member.size
                need(total_size <= MAX_ARCHIVE, 'WITNESS')
                nodes[name] = member
            # Require complete end markers and reject hidden trailing archive/data.
            need(0 <= archive.offset <= before['bytes'] - 1024, 'WITNESS')
            stream.seek(archive.offset)
            tail_bytes = 0
            while True:
                part = stream.read(1048576)
                if not part:
                    break
                tail_bytes += len(part)
                need(not part.strip(b'\0'), 'WITNESS')
                work_check()
            need(tail_bytes >= 1024, 'WITNESS')

            def resolve(name, allow_missing=False):
                pending = clean(name).split('/')
                done = []
                hops = 0
                while pending:
                    work_check()
                    part = pending.pop(0)
                    if part in ('', '.'):
                        continue
                    if part == '..':
                        need(done, 'WITNESS')
                        done.pop()
                        continue
                    here = '/'.join(done + [part])
                    info = nodes.get(here)
                    if info is not None and (info.issym() or info.islnk()):
                        hops += 1
                        need(hops <= 40, 'WITNESS')
                        # Resolve preceding symbolic components before applying '..'.
                        target_parts = info.linkname.split('/')
                        if info.islnk() or info.linkname.startswith('/'):
                            done = []
                        pending = target_parts + pending
                    else:
                        need(not pending or info is None or info.isdir(), 'WITNESS')
                        done.append(part)
                result = '/'.join(done)
                if allow_missing and result not in nodes:
                    return None
                need(result in nodes, 'WITNESS')
                return result

            def content(name, limit=1048576):
                nonlocal payload_size
                resolved = resolve(name)
                member = nodes[resolved]
                need(member.isfile() and 0 < member.size <= limit, 'WITNESS')
                if resolved not in cache:
                    handle = archive.extractfile(member)
                    need(handle is not None, 'WITNESS')
                    with handle:
                        data = handle.read(limit + 1)
                    need(len(data) == member.size and len(data) <= limit, 'WITNESS')
                    payload_size += len(data)
                    need(payload_size <= 16 * 1048576, 'WITNESS')
                    cache[resolved] = data
                work_check()
                return resolved, cache[resolved]

            def metadata(name):
                nonlocal emitted_payload_size
                _resolved, raw = content(name)
                # Preserve the observed installation path even for cache/venv hardlinks.
                emitted_payload_size += len(raw)
                need(emitted_payload_size <= 16 * 1048576, 'WITNESS')
                return {'path': '/' + clean(name), 'sha256': digest(raw), 'bytes': len(raw),
                        'data_b64': base64.b64encode(raw).decode('ascii')}

            def binary(requested):
                resolved = resolve(requested)
                member = nodes[resolved]
                need(member.isfile() and 0 < member.size <= 256 * 1048576 and
                     member.mode & 0o111 and not member.mode & 0o6000, 'WITNESS')
                handle = archive.extractfile(member)
                need(handle is not None, 'WITNESS')
                sha = hashlib.sha256()
                count = 0
                magic = b''
                with handle:
                    while True:
                        part = handle.read(1048576)
                        if not part:
                            break
                        if not magic:
                            magic = part[:20]
                        count += len(part)
                        need(count <= member.size, 'WITNESS')
                        sha.update(part)
                        work_check()
                need(count == member.size and magic[:4] == b'\x7fELF' and magic[4:6] == b'\x02\x01' and
                     magic[18:20] == b'\x3e\x00', 'WITNESS')
                aliases = {clean(requested), resolved}
                for candidate, entry in nodes.items():
                    if entry.issym() or entry.islnk():
                        target = resolve(candidate, allow_missing=True)
                        if target is None:
                            # Only an unrelated dangling target is ignored; work/deadline errors propagate.
                            continue
                        if target == resolved:
                            aliases.add(candidate)
                        if nodes[target].isdir() and resolved.startswith(target + '/'):
                            proposed = candidate + resolved[len(target):]
                            if resolve(proposed) == resolved:
                                aliases.add(proposed)
                        need(len(aliases) <= 32, 'WITNESS')
                    work_check()
                return {'requested_path': requested, 'resolved_path': '/' + resolved,
                        'aliases': sorted('/' + value for value in aliases), 'sha256': sha.hexdigest(),
                        'bytes': count, 'mode': member.mode & 0o7777, 'executable': True}

            os_release = metadata('/etc/os-release')
            version_path, version_raw = content('/usr/local/include/python3.11/patchlevel.h')
            version_text = version_raw.decode('utf-8')
            components = []
            for key in ('PY_MAJOR_VERSION', 'PY_MINOR_VERSION', 'PY_MICRO_VERSION'):
                matches = re.findall(r'^#define\s+' + key + r'\s+([0-9]{1,3})\s*$', version_text, re.M)
                need(len(matches) == 1, 'WITNESS')
                components.append(int(matches[0]))
            versions = re.findall(r'^#define\s+PY_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', version_text, re.M)
            version = '.'.join(str(value) for value in components)
            need(components[:2] == [3, 11] and versions == [version] and
                 '#define PY_VERSION_HEX' in version_text, 'WITNESS')
            _venv_path, venv_raw = content('/app/integrations/sycope/.venv/pyvenv.cfg')
            venv_text = venv_raw.decode('utf-8')
            venv_fields = {}
            for line in venv_text.splitlines():
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                need('=' in line, 'WITNESS')
                key, value = (part.strip() for part in line.split('=', 1))
                need(re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', key) is not None and
                     key not in venv_fields and value, 'WITNESS')
                venv_fields[key] = value
            observed_versions = [venv_fields[key] for key in ('version', 'version_info') if key in venv_fields]
            need(observed_versions and all(re.fullmatch(re.escape(version) + r'(?:\.final\.0)?', value)
                 for value in observed_versions), 'WITNESS')
            need(venv_fields.get('implementation') == 'CPython' and
                 venv_fields.get('include-system-site-packages') == 'false' and
                 venv_fields.get('home', '').rstrip('/') == '/usr/local/bin' and
                 resolve('/app/integrations/sycope/.venv/bin/python') ==
                 resolve('/usr/local/bin/python3.11'), 'WITNESS')
            interpreter = nodes[resolve('/app/integrations/sycope/.venv/bin/python')]
            need(interpreter.isfile() and 0 < interpreter.size <= 256 * 1048576 and
                 interpreter.mode & 0o111 and not interpreter.mode & 0o6000, 'WITNESS')
            python_metadata = []
            node_metadata = []
            node_roots = set()
            node_runtime = set()
            uncovered_node_metadata = False
            for name, member in sorted(nodes.items()):
                if (member.isfile() or member.issym() or member.islnk()) and name.endswith('.dist-info/METADATA'):
                    python_metadata.append(metadata(name))
                parts = name.split('/')
                # No successful Python coverage claim for an unhandled metadata format.
                need(not any(part.endswith(('.egg-info', '.egg')) for part in parts), 'WITNESS')
                if (member.isfile() or member.issym() or member.islnk()) and parts[-1] in (
                        'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'):
                    if 'node_modules' not in parts or parts[-1] != 'package.json':
                        uncovered_node_metadata = True
                if 'node_modules' in parts:
                    node_roots.add('/'.join(parts[:parts.index('node_modules') + 1]))
                    if parts[-1] == 'package.json' and (member.isfile() or member.issym() or member.islnk()):
                        node_metadata.append(metadata(name))
                if parts[-1] in ('node', 'nodejs') and (member.isfile() or member.issym() or member.islnk()):
                    resolved = resolve(name)
                    actual = nodes[resolved]
                    if actual.isfile() and actual.mode & 0o111:
                        node_runtime.add('/' + name)
                need(len(python_metadata) + len(node_metadata) <= 4096, 'WITNESS')
                work_check()
            need(python_metadata, 'WITNESS')
            node_state = ('UNKNOWN' if uncovered_node_metadata else 'PRESENT' if node_runtime or node_metadata
                          else 'UNKNOWN' if node_roots else 'ABSENT')
            result = {'image_id': image_id, 'rootfs_sha256': root_hash, 'rootfs_bytes': before['bytes'],
                      'member_count': member_count, 'complete': True, 'os_release': os_release,
                      'python': {'version': version, 'implementation': 'cpython',
                        'platform': {'os_name': 'posix', 'sys_platform': 'linux', 'platform_system': 'Linux',
                                     'platform_machine': 'x86_64', 'platform_python_implementation': 'CPython'},
                        'version_metadata_sha256': digest(version_raw),
                        'venv': '/app/integrations/sycope/.venv', 'metadata': python_metadata},
                      'uv': binary('/bin/uv'), 'uvx': binary('/bin/uvx'),
                      'node': {'applicability': node_state, 'runtime_paths': sorted(node_runtime),
                               'metadata': node_metadata}}
        need(info_identity(os.fstat(stream.fileno())) == before, 'WITNESS')
    need(file_identity(path) == before and hash_file(path, MAX_ARCHIVE) == root_hash, 'WITNESS')
    need(len(canonical(result)) <= 16 * 1048576, 'WITNESS')
    return result

def run_witness_controls(write_fixture):
    """Exercise this same reader with finite synthetic TAR data on the hosted runner."""
    import io

    image_id = 'sha256:' + '1' * 64
    image_info = {'Os': 'linux', 'Architecture': 'amd64'}
    venv = 'app/integrations/sycope/.venv'
    cache_metadata = 'root/.cache/uv/example-1.0.dist-info/METADATA'
    installed_metadata = venv + '/lib/python3.11/site-packages/example-1.0.dist-info/METADATA'
    header = (b'#define PY_MAJOR_VERSION 3\n#define PY_MINOR_VERSION 11\n'
              b'#define PY_MICRO_VERSION 16\n#define PY_VERSION "3.11.16"\n'
              b'#define PY_VERSION_HEX 0x030b10f0\n')
    cfg = (b'home = /usr/local/bin\nimplementation = CPython\nversion_info = 3.11.16\n'
           b'include-system-site-packages = false\nuv = 0.12.8\n')
    package = b'Metadata-Version: 2.4\nName: example\nVersion: 1.0\n'
    elf = bytearray(64)
    elf[:6] = b'\x7fELF\x02\x01'
    elf[18:20] = b'\x3e\x00'
    entries = [
        ('bin', 'symlink', 'usr/bin'),
        ('usr', 'dir', b''), ('usr/bin', 'dir', b''), ('usr/lib', 'dir', b''),
        ('usr/include', 'dir', b''), ('usr/sbin', 'dir', b''),
        ('usr/bin/uv', 'file', bytes(elf)), ('usr/bin/uvx', 'file', bytes(elf) + b'uvx'),
        ('usr/sbin/uv', 'symlink', '../bin/uv'), ('prefix', 'symlink', 'usr/include'),
        ('rel-uv', 'symlink', 'prefix/../sbin/uv'),
        ('etc/os-release', 'file', b'ID=debian\nVERSION_ID="13"\n'),
        ('usr/local/include/python3.11/patchlevel.h', 'file', header),
        ('usr/local/bin/python3.11', 'file', bytes(elf) + b'python'),
        (venv + '/bin/python', 'symlink', '/usr/local/bin/python3.11'),
        (venv + '/pyvenv.cfg', 'file', cfg),
        (cache_metadata, 'file', package), (installed_metadata, 'hardlink', cache_metadata),
    ]

    def tar_bytes(rows):
        sink = io.BytesIO()
        with tarfile.open(fileobj=sink, mode='w', format=tarfile.PAX_FORMAT) as output:
            for name, kind, value in rows:
                item = tarfile.TarInfo(name)
                item.mode = (0o644 if kind == 'nonexec' else 0o755
                             if kind != 'file' or name.endswith(('uv', 'uvx', 'python3.11')) else 0o644)
                if kind == 'dir':
                    item.type = tarfile.DIRTYPE
                    output.addfile(item)
                elif kind in ('symlink', 'hardlink'):
                    item.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                    item.linkname = value
                    output.addfile(item)
                else:
                    item.size = len(value)
                    output.addfile(item, io.BytesIO(value))
            logical_end = output.offset
        return sink.getvalue(), logical_end

    cases = 0
    complete, logical_end = tar_bytes(entries)
    observed = inspect_rootfs(write_fixture('valid-hardlink.tar', complete), image_id, image_info)
    paths = [row['path'] for row in observed['python']['metadata']]
    need(len(paths) == len(set(paths)) == 2 and '/' + installed_metadata in paths and
         '/' + cache_metadata in paths and '/rel-uv' in observed['uv']['aliases'] and
         observed['node']['applicability'] == 'ABSENT' and observed['complete'] is True, 'WITNESS')
    cases += 1
    node_tar, _end = tar_bytes(entries + [('opt/app/package.json', 'file', b'{"name":"example"}')])
    node = inspect_rootfs(write_fixture('uncovered-node.tar', node_tar), image_id, image_info)
    need(node['node']['applicability'] == 'UNKNOWN', 'WITNESS')
    cases += 1

    def rejected(name, raw):
        nonlocal cases
        try:
            inspect_rootfs(write_fixture(name, raw), image_id, image_info)
        except Failure as error:
            if type(error) is not Failure or error.code != 'WITNESS':
                raise
            cases += 1
            return
        raise Failure('WITNESS')

    traversal, _end = tar_bytes(entries + [('../escape', 'file', b'no')])
    rejected('member-traversal.tar', traversal)
    duplicate, _end = tar_bytes(entries + [('usr/bin/uv', 'file', bytes(elf))])
    rejected('duplicate-member.tar', duplicate)
    duplicate_root, _end = tar_bytes([('.', 'dir', b''), ('./', 'dir', b'')] + entries)
    rejected('duplicate-root.tar', duplicate_root)
    rejected('trailing-data.tar', complete + b'x' * 512)
    rejected('missing-end-marker.tar', complete[:logical_end])
    wrong_impl = [(name, kind, value.replace(b'CPython', b'PyPy') if name.endswith('pyvenv.cfg') else value)
                  for name, kind, value in entries]
    wrong, _end = tar_bytes(wrong_impl)
    rejected('wrong-implementation.tar', wrong)
    directory_interpreter = [(name, 'dir' if name == 'usr/local/bin/python3.11' else kind,
                              b'' if name == 'usr/local/bin/python3.11' else value)
                             for name, kind, value in entries]
    directory_tar, _end = tar_bytes(directory_interpreter)
    rejected('directory-interpreter.tar', directory_tar)
    nonexec_interpreter = [(name, 'nonexec' if name == 'usr/local/bin/python3.11' else kind, value)
                           for name, kind, value in entries]
    nonexec_tar, _end = tar_bytes(nonexec_interpreter)
    rejected('nonexec-interpreter.tar', nonexec_tar)
    unsupported, _end = tar_bytes(entries + [('usr/local/lib/python3.11/site-packages/old.egg-info', 'dir', b'')])
    rejected('unsupported-python.tar', unsupported)
    large_package = package + b'x' * (1048576 - len(package))
    large_rows = [(name, kind, large_package if name == cache_metadata else value)
                  for name, kind, value in entries]
    large_rows += [('extra/example-' + str(index) + '.dist-info/METADATA', 'hardlink', cache_metadata)
                   for index in range(17)]
    repeated, _end = tar_bytes(large_rows)
    rejected('repeated-metadata-bound.tar', repeated)
    need(cases == 12, 'WITNESS')
    return {'status': 'PASS', 'case_count': cases, 'passed': cases, 'failed': 0}


def capture_controls():
    """Hosted-only owned-capture limits; expected errors never reset real scan flags."""
    namespace = dict(globals())
    namespace.update(CANCELLED=False, UNCERTAIN=False)
    own = types.FunctionType(capture.__code__, namespace)
    own.__kwdefaults__ = dict(capture.__kwdefaults__)
    namespace['capture'] = own
    def childless():
        try:
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return
        raise Failure('INTERNAL')
    childless()
    py = str(Path(sys.executable).resolve(strict=True))
    code, raw, err, _elapsed = own([py, '-I', '-B', '-c',
        'import os;os.write(1,b"x"*(3*1024*1024))'], 30, stdout_cap=4 * 1048576)
    need(code == 0 and raw == b'x' * (3 * 1048576) and err == b'' and namespace['UNCERTAIN'] is False,
         'INTERNAL')
    childless()
    for channel, count, stdout_cap, stderr_cap in ((1, 64 * 1048576 + 1, 64 * 1048576, 1048576),
                                                  (2, 2 * 1048576 + 1, 1048576, 2 * 1048576)):
        program = ('import os\nleft=' + str(count) + '\nwhile left:\n '
                   'part=b"x"*min(left,65536);left-=os.write(' + str(channel) + ',part)\n')
        try:
            own([py, '-I', '-B', '-c', program], 30, stdout_cap=stdout_cap, stderr_cap=stderr_cap)
        except Failure as error:
            need(error.code == 'CAPTURE_CAP' and namespace['UNCERTAIN'] is True, 'INTERNAL')
        else:
            raise Failure('INTERNAL')
        childless()
        namespace['UNCERTAIN'] = False  # Only this isolated expected-negative test namespace.
    return {'status': 'C04_HOST_CAPTURE_CONTROLS_PASSED', 'case_count': 3, 'passed': 3, 'failed': 0}


def report_directory():
    path = Path(os.environ['C04_REPORT_DIR'])
    info = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(info.st_mode) and
         info.st_uid == UID and stat.S_IMODE(info.st_mode) == 0o700 and
         str(info.st_dev) == os.environ['C04_REPORT_DEV'] and
         str(info.st_ino) == os.environ['C04_REPORT_INO'] and
         str(info.st_uid) == os.environ['C04_REPORT_UID'], 'BOOTSTRAP')
    return path, (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def save_safe_result(value):
    raw = canonical(value) + b'\n'
    accepted = REDUCER['validate_safe_summary'](raw)
    need(accepted['valid'] is True and accepted['report'] == value and len(raw) <= 1048576, 'INTERNAL')
    path, expected = report_directory()
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temp = 'summary-' + secrets.token_hex(16) + '.tmp'
    try:
        info = os.fstat(fd)
        need((info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) == expected, 'BOOTSTRAP')
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=fd)
        try:
            position = 0
            while position < len(raw):
                count = os.write(out, raw[position:])
                need(count > 0, 'INTERNAL')
                position += count
                work_check(True)
            os.fsync(out)
            need(os.fstat(out).st_size == len(raw), 'INTERNAL')
        finally:
            os.close(out)
        try:
            previous = os.stat('sdk-image-scan-receipt.json', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            previous = None
        if previous is not None:
            need(stat.S_ISREG(previous.st_mode) and previous.st_nlink == 1 and previous.st_uid == UID and
                 stat.S_IMODE(previous.st_mode) == 0o600, 'INTERNAL')
        os.replace(temp, 'sdk-image-scan-receipt.json', src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        current, actual = report_directory()
        need(current == path and actual == expected, 'INTERNAL')
    finally:
        os.close(fd)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def main():
    global ENV, END, WORK_END, DOCKER, UID, GID, PHASE, UNCERTAIN
    UID, GID = os.getuid(), os.getgid()
    need(UID >= 1000 and GID >= 1000 and len(os.listdir('/proc/self/task')) == 1, 'BOOTSTRAP')
    END = time.monotonic() + 3000
    WORK_END = END - 240
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, END - time.monotonic()))
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    os.umask(0o077)
    # Host-process limit only: bounds Docker CLI archive files, never the daemon-created scanner/DB.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
    result = REDUCER['validate_scan_evidence']({}, None, None)
    save_safe_result(result)  # A typed ERROR exists before Docker, source parsing or selftests.
    evidence, report_raw, version_raw = {}, None, None
    root = None
    image = None
    image_intent = None
    before = None
    archive = None
    archive_row = None
    context = None
    try:
        controls = REDUCER['run_data_controls']()
        need(type(controls) is dict and set(controls) == {'status', 'case_count', 'passed', 'failed'} and
             controls['status'] == 'C04_REDUCER_DATA_CONTROLS_PASSED' and
             type(controls['case_count']) is type(controls['passed']) is type(controls['failed']) is int and
             0 < controls['case_count'] == controls['passed'] <= 4096 and controls['failed'] == 0, 'INTERNAL')
        runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
        checkout = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
        need(runner.is_dir() and not runner.is_symlink() and not runner.is_relative_to(checkout), 'BOOTSTRAP')
        root = Path(tempfile.mkdtemp(prefix='trueid-c04-', dir=runner))
        root_info = root.stat()
        need(root.resolve(strict=True) == root and root.parent == runner and root_info.st_uid == UID and
             stat.S_IMODE(root_info.st_mode) == 0o700, 'BOOTSTRAP')
        for name in ('home', 'docker-config', 'input', 'control', 'cache'):
            (root / name).mkdir(mode=0o700)
        original_home = Path(os.environ['HOME'])
        original_config = Path(os.environ.get('DOCKER_CONFIG', str(original_home / '.docker')))
        chosen = shutil.which('docker')
        need(chosen is not None, 'TOOL')
        docker_path = Path(chosen).resolve(strict=True)
        docker_raw = read_file(docker_path, MAX_HOST_TOOL, owned=False)
        DOCKER = str(docker_path)
        plugin_dirs = [original_config / 'cli-plugins', Path('/usr/libexec/docker/cli-plugins'),
                       Path('/usr/lib/docker/cli-plugins'), Path('/usr/local/libexec/docker/cli-plugins'),
                       Path('/usr/local/lib/docker/cli-plugins')]
        plugins = [p / 'docker-buildx' for p in plugin_dirs if (p / 'docker-buildx').is_file() and
                   os.access(p / 'docker-buildx', os.X_OK)]
        need(plugins, 'TOOL')
        original_plugin = plugins[0].resolve(strict=True)
        plugin_raw = read_file(original_plugin, MAX_HOST_TOOL, owned=False)
        plugin_dir = root / 'docker-config/cli-plugins'
        plugin_dir.mkdir(mode=0o700)
        write_new(plugin_dir / 'docker-buildx', plugin_raw, 0o500)
        ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(root / 'home'),
               'DOCKER_CONFIG': str(root / 'docker-config'), 'DOCKER_BUILDKIT': '1',
               'BUILDX_METADATA_PROVENANCE': 'max', 'LANG': 'C.UTF-8', 'NO_COLOR': '1',
               'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_TERMINAL_PROMPT': '0', 'PYTHONDONTWRITEBYTECODE': '1'}
        host_controls = capture_controls()
        fixture_dir = root / 'witness-controls'
        fixture_dir.mkdir(mode=0o700)
        def write_fixture(name, data):
            need(type(name) is str and re.fullmatch('[a-z][a-z0-9-]{0,48}\\.tar', name) is not None and
                 type(data) is bytes and 0 < len(data) <= 8 * 1048576, 'INTERNAL')
            target = fixture_dir / name
            write_new(target, data)
            return target
        witness_controls = run_witness_controls(write_fixture)
        need(type(witness_controls) is dict and set(witness_controls) == {'status','case_count','passed','failed'} and
             witness_controls['status'] == 'PASS' and type(witness_controls.get('case_count')) is int and
             type(witness_controls.get('passed')) is int and type(witness_controls.get('failed')) is int and
             0 < witness_controls['case_count'] == witness_controls['passed'] <= 4096 and witness_controls['failed'] == 0,
             'INTERNAL')
        print(json.dumps({'scope':'C04_SAME_CODE_CONTROLS_ONLY',
            'groups':{name:{key:value[key] for key in ('case_count','passed','failed')}
                      for name,value in (('reducer',controls),('capture',host_controls),('witness',witness_controls))}},
            sort_keys=True), flush=True)
        PHASE = 'TOOL'
        cli(['docker', 'version', '--format', '{{json .}}'])
        cli(['docker', 'buildx', 'version'])
        driver = cli(['docker', 'buildx', 'inspect', '--bootstrap'], 120)
        need(re.search(rb'^Driver:\s+docker\s*$', driver, re.M) is not None, 'TOOL')
        PHASE = 'SOURCE'
        context = root / 'context'
        head, before = source_context(checkout, context)
        evidence = {'schemaVersion': 1, 'source': {'head': head, 'before': before, 'after': None,
                     'context_sha256': digest(canonical(before))},
                    'build': None, 'image': None, 'archive': None, 'scanner': None, 'witness': None,
                    'inputs': {'uv_lock_b64': base64.b64encode(read_file(context / 'integrations/sycope/uv.lock', 1048576)).decode('ascii'),
                               'pyproject_b64': base64.b64encode(read_file(context / 'integrations/sycope/pyproject.toml', 1048576)).decode('ascii'),
                               'no_dev': True, 'selected_extras': []}, 'final': None, 'error_codes': []}
        write_new(root / 'control/trivy.yaml', b'{}\n')
        write_new(root / 'control/empty.ignore', b'')
        PHASE = 'BUILD'
        nonce = secrets.token_hex(16)
        tag = 'trueid-c04-sdk:' + nonce
        need(cli(['docker', 'image', 'ls', '--filter', 'reference=' + tag, '--format', '{{.ID}}']).strip() == b'', 'BUILD')
        image_intent = {'tag': tag, 'owner': nonce, 'id': None, 'acked': False, 'closed': False}
        write_new(root / 'image-intent.json', canonical(image_intent) + b'\n')
        code, _out, _err, _elapsed = cli(['docker', 'buildx', 'build', '--platform', 'linux/amd64',
            '--pull', '--no-cache', '--network', 'default', '--metadata-file', str(root / 'build-metadata.json'),
            '--iidfile', str(root / 'sdk.iid'), '--label', 'org.trueid.c04.image=' + nonce,
            '--file', str(context / 'integrations/sycope/Dockerfile'), '--tag', tag, '--load', str(context)],
            900, stdout_cap=2097152, allow_exit=True)
        image_intent['acked'] = True
        need(code == 0, 'BUILD')
        image = image_info(tag)
        image_intent['id'] = image['Id']
        iid = read_file(root / 'sdk.iid', 1024).decode('ascii').strip()
        need(iid == image['Id'] and image['Config']['Labels'].get('org.trueid.c04.image') == nonce, 'BUILD')
        evidence['image'] = {'id': image['Id'], 'os': image['Os'], 'architecture': image['Architecture'],
                             'variant': image.get('Variant', ''), 'iid_matches': True}
        PHASE = 'LINEAGE'
        metadata_raw = read_file(root / 'build-metadata.json', 4194304)
        evidence['build'] = {'actual_exit': code, 'metadata_sha256': digest(metadata_raw),
                             'metadata_config_image_id': image['Id'], 'uv': None}
        evidence['build']['uv'] = build_lineage(metadata_raw, image['Id'])
        PHASE = 'ARCHIVE'
        archive = root / 'input/sdk.tar'
        cli(['docker', 'image', 'save', '--output', str(archive), image['Id']], 300)
        archive_row = archive_image(archive, image['Id'])
        evidence['archive'] = archive_row
        PHASE = 'WITNESS'
        witness_intent, witness_cid = create_container(image['Id'], [], [], witness=True)
        try:
            rootfs = root / 'rootfs.tar'
            cli(['docker', 'export', '--output', str(rootfs), witness_cid], 300)
            witness_row = inspect_container(witness_cid)
            need(witness_row['State']['Status'] == 'created' and witness_row['State']['Running'] is False and
                 witness_row['State']['Pid'] == 0 and witness_row['Image'] == image['Id'], 'WITNESS')
            evidence['witness'] = inspect_rootfs(rootfs, image['Id'], image)
        finally:
            retire(witness_intent)
        PHASE = 'SCANNER'
        cli(['docker', 'pull', '--platform', 'linux/amd64', 'aquasec/trivy:0.57.1'], 120)
        tool = image_info('aquasec/trivy:0.57.1')['Id']
        mounts = [(root / 'input', '/input', True), (root / 'control', '/control', True),
                  (root / 'cache', '/cache', False)]
        need(not list((root / 'cache').iterdir()), 'DB')
        prefix = ['--config', '/control/trivy.yaml', '--cache-dir', '/cache']
        version_exit, before_version, _stderr, _elapsed = scanner(tool, prefix + ['version', '--format', 'json'], mounts)
        help_exit, help_raw, _stderr, _elapsed = scanner(tool, prefix + ['image', '--help'], mounts)
        flags = ['--config', '--cache-dir', '--input', '--scanners', '--pkg-types', '--list-all-pkgs', '--format', '--severity',
                 '--ignorefile', '--exit-code', '--timeout']
        before_json = owner_json(before_version, 1048576)
        need(version_exit == help_exit == 0 and type(before_json) is dict and
             type(before_json.get('Version')) is str and before_json['Version'] == '0.57.1' and
             all(flag.encode() in help_raw for flag in flags), 'TOOL')
        evidence['scanner'] = {'image_id': tool, 'version_before_b64': base64.b64encode(before_version).decode('ascii'),
            'version_before_exit': version_exit, 'help_sha256': digest(help_raw), 'help_flags': flags,
            'config_sha256': digest(b'{}\n'), 'ignore_sha256': digest(b''), 'empty_cache_before': True,
            'same_cache': True, 'db_download_scan_only': True, 'scan_exit': None, 'version_after_exit': None,
            'scan_utc': utc_now(), 'version_after_utc': None}
        code, report_raw, _stderr, _elapsed = scanner(tool, prefix + ['--timeout', '10m', 'image',
            '--input', '/input/sdk.tar', '--scanners', 'vuln', '--pkg-types', 'os,library', '--list-all-pkgs',
            '--format', 'json', '--severity', 'HIGH,CRITICAL', '--exit-code', '1', '--ignorefile', '/control/empty.ignore'],
            mounts, seconds=600, network='bridge', scan=True)
        evidence['scanner']['scan_exit'] = code
        PHASE = 'DB'
        version_exit, version_raw, _stderr, _elapsed = scanner(tool, prefix + ['version', '--format', 'json'], mounts)
        evidence['scanner']['version_after_exit'] = version_exit
        evidence['scanner']['version_after_utc'] = utc_now()
        need(version_exit == 0, 'DB')
        need(read_file(root / 'control/trivy.yaml', 1024) == b'{}\n' and
             read_file(root / 'control/empty.ignore', 1024, empty=True) == b'', 'TOOL')
        PHASE = 'SOURCE'
        evidence['source']['after'] = recheck_source(checkout, before)
        need(cli(['/usr/bin/git', '-C', str(checkout), 'rev-parse', 'HEAD']).decode('ascii').strip() == head, 'SOURCE')
        copied = {name: {'sha256': digest(read_file(context / name, 16 * 1048576, empty=True)),
                         'bytes': (context / name).stat().st_size} for name in sorted(before)}
        need(canonical(copied) == canonical(before), 'SOURCE')
        need(image_info(image['Id'])['Id'] == image['Id'] and image_info(tool)['Id'] == tool, 'BUILD')
        need(hash_file(archive, MAX_ARCHIVE) == archive_row['sha256'], 'ARCHIVE')
        evidence['archive']['unchanged'] = True
        need(read_file(docker_path, MAX_HOST_TOOL, owned=False) == docker_raw and
             read_file(original_plugin, MAX_HOST_TOOL, owned=False) == plugin_raw and
             read_file(plugin_dir / 'docker-buildx', MAX_HOST_TOOL) == plugin_raw, 'TOOL')
    except BaseException as error:
        fixed = {'BOOTSTRAP','SOURCE','TOOL','BUILD','LINEAGE','ARCHIVE','WITNESS','SCANNER','DB','JSON',
                 'OS','PYTHON','RUST','NODE','EXIT','OVERFLOW','CLEANUP','CANCELLED','INTERNAL'}
        code = error.code if type(error) is Failure and error.code in fixed else \
               'OVERFLOW' if type(error) is Failure and error.code == 'CAPTURE_CAP' else PHASE
        evidence.setdefault('error_codes', []).append(code if code in fixed else 'INTERNAL')
        print('C04 fixed failure category: ' + (code if code in fixed else 'INTERNAL'), file=sys.stderr, flush=True)
    finally:
        cleanup = True
        for intent in reversed(INTENTS):
            try:
                retire(intent)
            except BaseException:
                cleanup = False
        if image_intent is not None:
            try:
                found = cli(['docker', 'image', 'ls', '--no-trunc', '--filter',
                             'label=org.trueid.c04.image=' + image_intent['owner'], '--format', '{{.ID}}'], cleanup=True)
                ids = sorted(set(found.decode('ascii').splitlines()))
                need(len(ids) <= 1 and all(re.fullmatch('sha256:[0-9a-f]{64}', value) is not None for value in ids), 'CLEANUP')
                for value in ids:
                    row = owner_json(cli(['docker', 'image', 'inspect', value], cleanup=True))[0]
                    need(row['Id'] == value and row['Config']['Labels'].get('org.trueid.c04.image') == image_intent['owner'] and
                         (image_intent['id'] is None or image_intent['id'] == value) and
                         image_intent['tag'] in (row.get('RepoTags') or []), 'CLEANUP')
                    cli(['docker', 'image', 'rm', image_intent['tag']], cleanup=True)
                need(cli(['docker', 'image', 'ls', '--no-trunc', '--filter',
                          'label=org.trueid.c04.image=' + image_intent['owner'], '--format', '{{.ID}}'], cleanup=True).strip() == b'', 'CLEANUP')
                image_intent['closed'] = True
                if not image_intent['acked']:
                    UNCERTAIN = True
            except BaseException:
                cleanup = False
        closed = cleanup and not UNCERTAIN and all(intent['closed'] for intent in INTENTS)
        removed = False
        if root is not None and closed:
            try:
                current = root.lstat()
                need(root.resolve(strict=True) == root and root.parent == runner and
                     (current.st_dev, current.st_ino, current.st_uid) ==
                     (root_info.st_dev, root_info.st_ino, root_info.st_uid) and shutil.rmtree.avoids_symlink_attacks,
                     'CLEANUP')
                for current_path, dirs, _files in os.walk(root, topdown=True, followlinks=False):
                    Path(current_path).chmod(0o700)
                    work_check(True)
                shutil.rmtree(root)
                need(not root.exists() and not root.is_symlink(), 'CLEANUP')
                removed = True
            except BaseException:
                cleanup = False
        evidence['final'] = {'source_unchanged': bool((evidence.get('source') or {}).get('after')),
            'image_unchanged': bool(evidence.get('image') and (evidence.get('archive') or {}).get('unchanged')),
            'archive_unchanged': bool((evidence.get('archive') or {}).get('unchanged')),
            'owned_cli_drain': closed, 'containers_removed': all(intent['closed'] for intent in INTENTS),
            'owned_image_removed': image_intent is not None and image_intent['closed'],
            'private_context_removed': removed and cleanup, 'cancelled': CANCELLED, 'uncertain': UNCERTAIN}
        if not closed or not removed or not cleanup:
            evidence.setdefault('error_codes', []).append('CLEANUP')
        result = REDUCER['validate_scan_evidence'](evidence, report_raw, version_raw)
        if CANCELLED or UNCERTAIN:
            need(result['status'] != 'PASS', 'INTERNAL')
        save_safe_result(result)
    # Alarm remains armed through cleanup, parse, fsync and this normal return.
    return 0 if result['status'] == 'PASS' and not CANCELLED and not UNCERTAIN else 1


if __name__ == '__main__':
    try:
        result_code = main()
    except BaseException:
        print('C04 producer aborted before safe normal finalization', file=sys.stderr, flush=True)
        result_code = 2
    sys.exit(result_code)

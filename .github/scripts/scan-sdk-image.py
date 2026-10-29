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

REDUCER_SOURCE = '"""Passive stdlib SDK scan reducer and private same-code DATA controls.\n\nNo file/process/network/product/package execution. The workflow owner supplies\ncomplete observed buffers only after owned cleanup; no raw input is returned.\n"""\nimport base64\nimport copy\nimport datetime\nimport hashlib\nimport json\nimport math\nimport re\nimport tomllib\n\nSR_SCOPE = \'C04_SDK_IMAGE_SCAN\'\nSR_RAW_MAX = 67108864\nSR_VERSION_MAX = 1048576\nSR_SUMMARY_MAX = 1048576\nSR_WITNESS_MAX = 16777216\nSR_MEMBER_MAX = 1048576\nSR_ARCHIVE_MAX = 4294967296\nSR_CONFIG_MAX = 4194304\nSR_LAYER_MAX = 256\nSR_INDEX_MEDIA = (\'application/vnd.oci.image.index.v1+json\',\'application/vnd.docker.distribution.manifest.list.v2+json\')\nSR_MANIFEST_MEDIA = (\'application/vnd.oci.image.manifest.v1+json\',\'application/vnd.docker.distribution.manifest.v2+json\')\nSR_CONFIG_MEDIA = (\'application/vnd.oci.image.config.v1+json\',\'application/vnd.docker.container.image.v1+json\')\nSR_LAYER_MEDIA = (\'application/vnd.oci.image.layer.v1.tar\',\'application/vnd.docker.image.rootfs.diff.tar\',\n                  \'application/vnd.oci.image.layer.v1.tar+gzip\',\'application/vnd.docker.image.rootfs.diff.tar.gzip\')\nSR_ERRORS = (\'BOOTSTRAP\',\'SOURCE\',\'TOOL\',\'BUILD\',\'LINEAGE\',\'ARCHIVE\',\'WITNESS\',\n             \'SCANNER\',\'DB\',\'JSON\',\'OS\',\'PYTHON\',\'RUST\',\'NODE\',\'EXIT\',\'OVERFLOW\',\n             \'CLEANUP\',\'CANCELLED\',\'INTERNAL\')\nSR_LIMITS = [\n    \'Python interpreter, standard library and arbitrary vendored code are not proven by installed-distribution inventory.\',\n    \'Rust build-only dependencies are outside cargo-auditable runtime inventory.\',\n    \'OS support is the selected Trivy scanner table at scan time, not current vendor support or universal advisory completeness.\'\n]\nSR_VENV = \'/app/integrations/sycope/.venv\'\nSR_LOCK = \'integrations/sycope/uv.lock\'\nSR_PROJECT = \'integrations/sycope/pyproject.toml\'\nSR_REQUIRED_SOURCE = {\'.dockerignore\',\'integrations/sycope/Dockerfile\',\n                      \'integrations/sycope/.python-version\',SR_LOCK,SR_PROJECT}\nSR_HELP_FLAGS = {\'--input\',\'--scanners\',\'--pkg-types\',\'--list-all-pkgs\',\n                 \'--format\',\'--severity\',\'--exit-code\',\'--cache-dir\',\'--config\',\'--ignorefile\'}\n# Exact requested Trivy v0.57.1 Debian table for the SDK\'s modern Debian profile.\nSR_DEBIAN_EOL = {\'7\':\'2018-05-31T23:59:59Z\',\'8\':\'2020-06-30T23:59:59Z\',\n                 \'9\':\'2022-06-30T23:59:59Z\',\'10\':\'2024-06-30T23:59:59Z\',\n                 \'11\':\'2026-08-14T23:59:59Z\',\'12\':\'2028-06-10T23:59:59Z\',\n                 \'13\':\'3000-01-01T23:59:59Z\'}\nSR_ID_KEYS = (\'source_head\',\'source_sha256\',\'docker_image_id\',\'docker_id_kind\',\'archive_identity_profile\',\n              \'sdk_target_digest\',\'sdk_platform_manifest_digest\',\'sdk_config_image_id\',\'trivy_report_image_id\',\n              \'trivy_report_image_id_domain\',\'iid_image_id\',\'metadata_image_id\',\'metadata_image_key\',\n              \'metadata_image_role\',\'archive_sha256\',\'scanner_docker_image_id\',\'report_sha256\',\'version_sha256\',\n              \'witness_sha256\',\'build_metadata_sha256\',\'uv_material_digest\',\'uv_platform_manifest_digest\')\n\n\nclass SRRejected(Exception):\n    def __init__(self, code):\n        self.code = code if code in SR_ERRORS else \'INTERNAL\'\n\n\ndef sr_need(value, code):\n    if not value:\n        raise SRRejected(code)\n\n\ndef sr_closed(value, keys, code):\n    sr_need(type(value) is dict and set(value) == set(keys), code)\n\n\ndef sr_int(value, low, high, code):\n    sr_need(type(value) is int and low <= value <= high, code)\n    return value\n\n\ndef sr_hash(value, code):\n    sr_need(type(value) is str and re.fullmatch(\'[0-9a-f]{64}\', value) is not None, code)\n    return value\n\n\ndef sr_image(value, code):\n    sr_need(type(value) is str and re.fullmatch(\'sha256:[0-9a-f]{64}\', value) is not None, code)\n    return value\n\n\ndef sr_digest(raw):\n    return hashlib.sha256(raw).hexdigest()\n\n\ndef sr_canonical(value):\n    return json.dumps(value,sort_keys=True,separators=(\',\',\':\'),ensure_ascii=True,allow_nan=False).encode(\'ascii\')\n\n\ndef sr_text(value, limit, code, empty=False):\n    sr_need(type(value) is str and (empty or bool(value)) and len(value) <= limit and\n            \'\\0\' not in value and not any(0xD800 <= ord(c) <= 0xDFFF for c in value), code)\n    return value\n\n\ndef sr_walk(value, code=\'JSON\'):\n    count = [0]\n    def walk(item, depth=0):\n        count[0] += 1\n        sr_need(depth <= 32 and count[0] <= 2000000, code)\n        if type(item) is dict:\n            sr_need(len(item) <= 200000, code)\n            for key, child in item.items():\n                sr_text(key,65536,code,True); walk(child,depth+1)\n        elif type(item) is list:\n            sr_need(len(item) <= 200000, code)\n            for child in item: walk(child,depth+1)\n        elif type(item) is str:\n            sr_text(item,SR_RAW_MAX,code,True)\n        elif type(item) is int:\n            sr_need(abs(item) <= 2**63-1, code)\n        elif type(item) is float:\n            sr_need(math.isfinite(item) and abs(item) <= 2**63-1, code)\n        else:\n            sr_need(item is None or type(item) is bool, code)\n    walk(value)\n\n\ndef sr_json(raw, cap):\n    sr_need(type(raw) is bytes and 0 < len(raw) <= cap, \'JSON\')\n    try:\n        text = raw.decode(\'utf-8\',\'strict\')\n        # Bound depth before decoding; braces inside strings do not count.\n        depth = 0; quoted = False; escaped = False\n        for char in text:\n            if quoted:\n                if escaped: escaped = False\n                elif char == \'\\\\\': escaped = True\n                elif char == \'"\': quoted = False\n            elif char == \'"\': quoted = True\n            elif char in \'[{\':\n                depth += 1; sr_need(depth <= 32,\'JSON\')\n            elif char in \']}\': depth -= 1\n        def pairs(rows):\n            result = {}\n            for key, value in rows:\n                sr_need(key not in result,\'JSON\'); result[key] = value\n            return result\n        def constant(_value):\n            raise SRRejected(\'JSON\')\n        value = json.loads(text,object_pairs_hook=pairs,parse_constant=constant)\n        sr_walk(value)\n        return value\n    except (UnicodeError,ValueError,RecursionError,OverflowError):\n        raise SRRejected(\'JSON\') from None\n\n\ndef sr_b64(value, cap, code):\n    sr_text(value,4*((cap+2)//3),code)\n    sr_need(value.isascii() and len(value) % 4 == 0 and re.fullmatch(r\'[A-Za-z0-9+/]*={0,2}\',value) is not None,code)\n    padding = len(value)-len(value.rstrip(\'=\'))\n    sr_need(0 < 3*(len(value)//4)-padding <= cap,code)\n    try: raw = base64.b64decode(value,validate=True)\n    except (ValueError,UnicodeError): raise SRRejected(code) from None\n    sr_need(len(raw) == 3*(len(value)//4)-padding and base64.b64encode(raw).decode(\'ascii\') == value,code)\n    return raw\n\n\ndef sr_evidence_bound(value):\n    # Measure the complete canonical envelope before decoding any payload.\n    sr_walk(value)\n    count = 0\n    encoder = json.JSONEncoder(sort_keys=True,separators=(\',\',\':\'),ensure_ascii=True,allow_nan=False)\n    for piece in encoder.iterencode(value):\n        count += len(piece)\n        sr_need(count <= SR_WITNESS_MAX,\'OVERFLOW\')\n\n\ndef sr_path(value, code, absolute=True):\n    sr_text(value,4096,code)\n    sr_need(not any(ord(c) < 32 or ord(c) == 127 for c in value) and\n            value.startswith(\'/\') is absolute and not value.endswith(\'/\'),code)\n    parts = value.split(\'/\')[1:] if absolute else value.split(\'/\')\n    sr_need(parts and all(part not in (\'\',\'.\',\'..\') for part in parts),code)\n    return value\n\n\ndef sr_timestamp(value, code):\n    sr_text(value,40,code)\n    match = re.fullmatch(r\'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,9}))?(?:Z|\\+00:00)\',value)\n    sr_need(match is not None,code)\n    try:\n        stamp = datetime.datetime(*(int(x) for x in match.groups()[:6]),tzinfo=datetime.timezone.utc)\n    except ValueError: raise SRRejected(code) from None\n    sr_need(stamp.year > 1,code)\n    return stamp,int((match.group(7) or \'\').ljust(9,\'0\') or \'0\')\n\n\ndef sr_name(value, code, python=False):\n    sr_text(value,256,code)\n    sr_need(re.fullmatch(r\'(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._+:-]*\',value) is not None,code)\n    if python:\n        sr_need(re.fullmatch(r\'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\',value) is not None,code)\n        return re.sub(r\'[-_.]+\',\'-\',value).lower()\n    return value\n\n\ndef sr_version(value, code, empty=False):\n    sr_text(value,512,code,empty)\n    sr_need(not value or re.fullmatch(r\'[A-Za-z0-9][A-Za-z0-9._+!~:,<>=|* -]*\',value) is not None,code)\n    return value\n\n\ndef sr_pairs(packages, code, python=False):\n    sr_need(type(packages) is list and len(packages) <= 200000,code)\n    result = set()\n    for row in packages:\n        sr_need(type(row) is dict and \'Name\' in row and \'Version\' in row,code)\n        result.add((sr_name(row[\'Name\'],code,python),sr_version(row[\'Version\'],code)))\n    return result\n\n\ndef sr_inventory_hash(pairs):\n    return sr_digest(sr_canonical([list(row) for row in sorted(pairs)]))\n\n\ndef sr_numeric_version(value):\n    sr_need(type(value) is str and 0 < len(value) <= 512 and\n            re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',value) is not None,\'PYTHON\')\n    return tuple(int(x) for x in value.split(\'.\'))\n\n\ndef sr_satisfies(version, specifier):\n    actual = sr_numeric_version(version)\n    sr_text(specifier,512,\'PYTHON\')\n    for item in specifier.split(\',\'):\n        match = re.fullmatch(r\'\\s*(>=|<=|==|!=|~=|>|<)\\s*([0-9]+(?:\\.[0-9]+)*(?:\\.\\*)?)\\s*\',item)\n        sr_need(match is not None,\'PYTHON\')\n        op, text = match.groups(); wild = text.endswith(\'.*\')\n        wanted = sr_numeric_version(text[:-2] if wild else text)\n        width = max(len(actual),len(wanted)); a = actual+(0,)*(width-len(actual)); b = wanted+(0,)*(width-len(wanted))\n        if wild:\n            sr_need(op in (\'==\',\'!=\'),\'PYTHON\'); equal = actual[:len(wanted)] == wanted\n            ok = equal if op == \'==\' else not equal\n        elif op == \'~=\':\n            sr_need(len(wanted) >= 2,\'PYTHON\')\n            upper = (wanted[0]+1,) if len(wanted) == 2 else wanted[:-2]+(wanted[-2]+1,)\n            u = upper+(0,)*(width-len(upper)); ok = a >= b and a < u\n        else:\n            ok = {\'>=\':a>=b,\'<=\':a<=b,\'==\':a==b,\'!=\':a!=b,\'>\':a>b,\'<\':a<b}[op]\n        sr_need(ok,\'PYTHON\')\n\n\ndef sr_requirement(value):\n    sr_text(value,1024,\'PYTHON\')\n    match = re.fullmatch(r\'([A-Za-z0-9][A-Za-z0-9._-]*)(.*)\',value)\n    sr_need(match is not None and not any(c in match.group(2) for c in \';[]@\'),\'PYTHON\')\n    name = sr_name(match.group(1),\'PYTHON\',True); spec = match.group(2).strip()\n    return name,spec\n\n\ndef sr_runtime_lock(lock_raw, project_raw, actual_python):\n    try:\n        lock = tomllib.loads(lock_raw.decode(\'utf-8\',\'strict\'))\n        manifest = tomllib.loads(project_raw.decode(\'utf-8\',\'strict\'))\n    except (ValueError,UnicodeError,RecursionError): raise SRRejected(\'PYTHON\') from None\n    sr_walk(lock,\'PYTHON\'); sr_walk(manifest,\'PYTHON\')\n    sr_need(type(lock) is dict and type(manifest) is dict,\'PYTHON\')\n    sr_int(lock.get(\'version\'),1,1,\'PYTHON\'); sr_need(type(lock.get(\'revision\')) is int and lock[\'revision\'] in (3,5),\'PYTHON\')\n    project = manifest.get(\'project\'); sr_need(type(project) is dict,\'PYTHON\')\n    sr_need(manifest.get(\'tool\',{}).get(\'uv\',{}).get(\'package\') is False,\'PYTHON\')\n    sr_need(not manifest.get(\'dependency-groups\') and not project.get(\'optional-dependencies\') and\n            not lock.get(\'resolution-markers\') and not lock.get(\'supported-markers\'),\'PYTHON\')\n    sr_satisfies(actual_python,project.get(\'requires-python\')); sr_satisfies(actual_python,lock.get(\'requires-python\'))\n    root_name = sr_name(project.get(\'name\'),\'PYTHON\',True); root_version = sr_version(project.get(\'version\'),\'PYTHON\')\n    sr_numeric_version(root_version)\n    packages = lock.get(\'package\'); sr_need(type(packages) is list and 1 <= len(packages) <= 100000,\'PYTHON\')\n    by_name = {}; root = None\n    for row in packages:\n        sr_need(type(row) is dict,\'PYTHON\')\n        name = sr_name(row.get(\'name\'),\'PYTHON\',True); version = sr_version(row.get(\'version\'),\'PYTHON\')\n        sr_numeric_version(version); sr_need(name not in by_name,\'PYTHON\'); by_name[name] = row\n        sr_need(not any(row.get(k) for k in (\'optional-dependencies\',\'dev-dependencies\',\'marker\',\'resolution-markers\')),\'PYTHON\')\n        if row.get(\'source\') == {\'virtual\':\'.\'}:\n            sr_need(root is None and name == root_name and version == root_version,\'PYTHON\'); root = row\n        else:\n            sr_need(row.get(\'source\') == {\'registry\':\'https://pypi.org/simple\'},\'PYTHON\')\n    sr_need(root is not None,\'PYTHON\')\n    def edges(row):\n        values = row.get(\'dependencies\',[]); sr_need(type(values) is list,\'PYTHON\'); found = []\n        for edge in values:\n            sr_closed(edge,(\'name\',),\'PYTHON\'); name = sr_name(edge[\'name\'],\'PYTHON\',True)\n            sr_need(name in by_name and name != root_name and name not in found,\'PYTHON\'); found.append(name)\n        return found\n    roots = edges(root); declarations = project.get(\'dependencies\')\n    sr_need(type(declarations) is list and declarations,\'PYTHON\')\n    required = {}\n    for declaration in declarations:\n        name,spec = sr_requirement(declaration); sr_need(name in by_name and name not in required,\'PYTHON\')\n        if spec: sr_satisfies(by_name[name][\'version\'],spec)\n        required[name] = spec\n    sr_need(set(roots) == set(required),\'PYTHON\')\n    declared = root.get(\'metadata\',{}).get(\'requires-dist\')\n    sr_need(type(declared) is list and len(declared) == len(required),\'PYTHON\')\n    metadata_names = set()\n    for row in declared:\n        sr_closed(row,(\'name\',\'specifier\'),\'PYTHON\'); name = sr_name(row[\'name\'],\'PYTHON\',True)\n        sr_need(name in required and name not in metadata_names and row[\'specifier\'] == required[name],\'PYTHON\')\n        metadata_names.add(name)\n    pending = list(roots); selected = set()\n    while pending:\n        name = pending.pop()\n        if name in selected: continue\n        selected.add(name); pending.extend(edges(by_name[name]))\n    sr_need(selected == set(by_name)-{root_name},\'PYTHON\')\n    return {(name,by_name[name][\'version\']) for name in selected}\n\n\ndef sr_member(row, code):\n    sr_closed(row,(\'path\',\'sha256\',\'bytes\',\'data_b64\'),code)\n    sr_path(row[\'path\'],code); size = sr_int(row[\'bytes\'],1,SR_MEMBER_MAX,code)\n    raw = sr_b64(row[\'data_b64\'],SR_MEMBER_MAX,code)\n    sr_need(len(raw) == size and sr_digest(raw) == sr_hash(row[\'sha256\'],code),code)\n    return raw\n\n\ndef sr_metadata_rows(rows):\n    sr_need(type(rows) is list and 1 <= len(rows) <= 200000,\'PYTHON\')\n    paths = set(); all_pairs = set(); venv_pairs = set(); venv_names = {}\n    for row in rows:\n        raw = sr_member(row,\'PYTHON\'); path = row[\'path\']\n        sr_need(path not in paths and re.search(r\'/[^/]+\\.dist-info/METADATA$\',path) is not None,\'PYTHON\'); paths.add(path)\n        try: text = raw.decode(\'utf-8\',\'strict\')\n        except UnicodeError: raise SRRejected(\'PYTHON\') from None\n        sr_text(text,SR_MEMBER_MAX,\'PYTHON\')\n        headers = {}; last = None\n        for line in text.splitlines():\n            if line == \'\': break\n            if line[:1] in (\' \',\'\\t\'):\n                sr_need(last is not None,\'PYTHON\'); headers[last][-1] += \'\\n\'+line; continue\n            sr_need(\':\' in line,\'PYTHON\'); key,value = line.split(\':\',1); key = key.lower()\n            sr_need(re.fullmatch(\'[a-z0-9-]+\',key) is not None,\'PYTHON\')\n            headers.setdefault(key,[]).append(value.strip()); last = key\n        sr_need(len(headers.get(\'name\',[])) == len(headers.get(\'version\',[])) == 1,\'PYTHON\')\n        pair = (sr_name(headers[\'name\'][0],\'PYTHON\',True),sr_version(headers[\'version\'][0],\'PYTHON\'))\n        all_pairs.add(pair)\n        if path.startswith(SR_VENV+\'/\'):\n            sr_need(pair[0] not in venv_names,\'PYTHON\'); venv_names[pair[0]] = pair[1]; venv_pairs.add(pair)\n    sr_need(all_pairs and venv_pairs,\'PYTHON\')\n    return all_pairs,venv_pairs\n\n\ndef sr_os_release(row):\n    sr_closed(row,(\'path\',\'sha256\',\'data_b64\'),\'OS\'); sr_path(row[\'path\'],\'OS\')\n    raw = sr_b64(row[\'data_b64\'],SR_MEMBER_MAX,\'OS\'); sr_need(sr_digest(raw) == sr_hash(row[\'sha256\'],\'OS\'),\'OS\')\n    try: text = raw.decode(\'utf-8\',\'strict\')\n    except UnicodeError: raise SRRejected(\'OS\') from None\n    sr_text(text,SR_MEMBER_MAX,\'OS\'); values = {}\n    for line in text.splitlines():\n        if not line.strip() or line.lstrip().startswith(\'#\'): continue\n        sr_need(\'=\' in line,\'OS\'); key,value = line.split(\'=\',1)\n        sr_need(re.fullmatch(\'[A-Z_][A-Z0-9_]*\',key) is not None and key not in values,\'OS\')\n        if value.startswith((\'"\',"\'")):\n            sr_need(len(value) >= 2 and value[-1] == value[0],\'OS\'); value = value[1:-1]\n        sr_need(\'\\\\\' not in value and \'\\0\' not in value,\'OS\'); values[key] = value\n    sr_need(values.get(\'ID\') == \'debian\' and re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',values.get(\'VERSION_ID\',\'\')) is not None,\'OS\')\n    return values[\'VERSION_ID\'].split(\'.\')[0]\n\n\ndef sr_node_rows(node):\n    sr_closed(node,(\'applicability\',\'metadata\',\'runtime_paths\'),\'NODE\')\n    sr_need(node[\'applicability\'] in (\'ABSENT\',\'PRESENT\') and type(node[\'metadata\']) is list and type(node[\'runtime_paths\']) is list,\'NODE\')\n    paths = set(); pairs = set()\n    for path in node[\'runtime_paths\']:\n        sr_path(path,\'NODE\'); sr_need(path not in paths,\'NODE\'); paths.add(path)\n    files = set()\n    for row in node[\'metadata\']:\n        raw = sr_member(row,\'NODE\'); sr_need(row[\'path\'] not in files and row[\'path\'].endswith(\'/package.json\') and \'/node_modules/\' in row[\'path\'],\'NODE\')\n        files.add(row[\'path\']); doc = sr_json(raw,SR_MEMBER_MAX); sr_need(type(doc) is dict,\'NODE\')\n        pairs.add((sr_name(doc.get(\'name\'),\'NODE\'),sr_version(doc.get(\'version\'),\'NODE\')))\n    if node[\'applicability\'] == \'ABSENT\': sr_need(not paths and not pairs and not files,\'NODE\')\n    else: sr_need(pairs and files,\'NODE\')\n    return pairs\n\n\ndef sr_tar_path(value):\n    sr_text(value,4096,\'ARCHIVE\')\n    sr_need(not value.startswith(\'/\') and not value.endswith(\'/\') and \'\\\\\' not in value and\n            not any(ord(c) < 32 or ord(c) == 127 for c in value) and\n            all(part not in (\'\',\'.\',\'..\') for part in value.split(\'/\')),\'ARCHIVE\')\n    return value\n\n\ndef sr_descriptor(value, media, cap=SR_ARCHIVE_MAX):\n    sr_closed(value,(\'media_type\',\'digest\',\'bytes\'),\'ARCHIVE\')\n    sr_need(type(value[\'media_type\']) is str and value[\'media_type\'] in media,\'ARCHIVE\')\n    sr_image(value[\'digest\'],\'ARCHIVE\'); sr_int(value[\'bytes\'],1,cap,\'ARCHIVE\')\n    return value\n\n\ndef sr_raw_descriptor(value, media, cap=SR_ARCHIVE_MAX):\n    sr_need(type(value) is dict and all(key in value for key in (\'mediaType\',\'digest\',\'size\')),\'ARCHIVE\')\n    sr_need(value.get(\'urls\') in (None,[]) and value.get(\'data\') in (None,\'\'),\'ARCHIVE\')\n    return sr_descriptor({\'media_type\':value[\'mediaType\'],\'digest\':value[\'digest\'],\'bytes\':value[\'size\']},media,cap)\n\n\ndef sr_archive_member(value, cap):\n    sr_closed(value,(\'path\',\'sha256\',\'bytes\'),\'ARCHIVE\')\n    sr_tar_path(value[\'path\']); sr_hash(value[\'sha256\'],\'ARCHIVE\'); sr_int(value[\'bytes\'],1,cap,\'ARCHIVE\')\n    return value\n\n\ndef sr_archive_blob(value, path=None):\n    sr_closed(value,(\'path\',\'sha256\',\'bytes\',\'data_b64\'),\'ARCHIVE\')\n    observed = sr_archive_member({key:value[key] for key in (\'path\',\'sha256\',\'bytes\')},SR_MEMBER_MAX)\n    if path is not None: sr_need(observed[\'path\'] == path,\'ARCHIVE\')\n    raw = sr_b64(value[\'data_b64\'],SR_MEMBER_MAX,\'ARCHIVE\')\n    sr_need(len(raw) == observed[\'bytes\'] and sr_digest(raw) == observed[\'sha256\'],\'ARCHIVE\')\n    return raw,sr_json(raw,SR_MEMBER_MAX)\n\n\ndef sr_descriptor_blob(value, media):\n    sr_closed(value,(\'descriptor\',\'blob\'),\'ARCHIVE\')\n    desc = sr_descriptor(value[\'descriptor\'],media,SR_MEMBER_MAX)\n    raw,doc = sr_archive_blob(value[\'blob\'],\'blobs/sha256/\'+desc[\'digest\'][7:])\n    sr_need(len(raw) == desc[\'bytes\'] and \'sha256:\'+sr_digest(raw) == desc[\'digest\'],\'ARCHIVE\')\n    sr_need(type(doc) is dict and type(doc.get(\'schemaVersion\')) is int and doc[\'schemaVersion\'] == 2 and\n            doc.get(\'mediaType\') == desc[\'media_type\'],\'ARCHIVE\')\n    return desc,doc\n\n\ndef sr_file_proof(value, archive):\n    sr_closed(value,(\'fd_before\',\'path_before\',\'fd_after\',\'path_after\',\'sha256_before\',\'sha256_after\',\n                     \'held_one_fd\',\'complete_outer_tar\'),\'ARCHIVE\')\n    sr_need(value[\'held_one_fd\'] is value[\'complete_outer_tar\'] is True,\'ARCHIVE\')\n    keys = (\'device\',\'inode\',\'uid\',\'gid\',\'mode\',\'links\',\'bytes\',\'mtime_ns\',\'ctime_ns\')\n    for name in (\'fd_before\',\'path_before\',\'fd_after\',\'path_after\'):\n        row = value[name]; sr_closed(row,keys,\'ARCHIVE\')\n        sr_int(row[\'device\'],0,2**63-1,\'ARCHIVE\'); sr_int(row[\'inode\'],1,2**63-1,\'ARCHIVE\')\n        sr_int(row[\'uid\'],1000,2**31-1,\'ARCHIVE\'); sr_int(row[\'gid\'],0,2**31-1,\'ARCHIVE\')\n        sr_int(row[\'mode\'],0o600,0o600,\'ARCHIVE\'); sr_int(row[\'links\'],1,1,\'ARCHIVE\')\n        sr_int(row[\'bytes\'],1,SR_ARCHIVE_MAX,\'ARCHIVE\')\n        for key in (\'mtime_ns\',\'ctime_ns\'): sr_int(row[key],0,2**63-1,\'ARCHIVE\')\n        sr_need(row == value[\'fd_before\'],\'ARCHIVE\')\n    sr_need(value[\'fd_before\'][\'bytes\'] == archive[\'bytes\'] and archive[\'bytes\'] >= 1024 and\n            archive[\'bytes\'] % 512 == 0,\'ARCHIVE\')\n    sr_need(sr_hash(value[\'sha256_before\'],\'ARCHIVE\') == sr_hash(value[\'sha256_after\'],\'ARCHIVE\') == archive[\'sha256\'],\'ARCHIVE\')\n\n\ndef sr_archive_roles(image, archive):\n    sr_closed(image,(\'id\',\'inspect_descriptor\',\'os\',\'architecture\',\'variant\'),\'ARCHIVE\')\n    docker_id = sr_image(image[\'id\'],\'ARCHIVE\')\n    sr_need(image[\'os\'] == \'linux\' and image[\'architecture\'] == \'amd64\' and image[\'variant\'] in (\'\',\'v1\'),\'ARCHIVE\')\n    sr_closed(archive,(\'sha256\',\'bytes\',\'unchanged\',\'config_image_id\',\'target_digest\',\n                       \'platform_manifest_digest\',\'docker_id_kind\',\'auth\'),\'ARCHIVE\')\n    sr_hash(archive[\'sha256\'],\'ARCHIVE\'); sr_int(archive[\'bytes\'],1,SR_ARCHIVE_MAX,\'ARCHIVE\')\n    sr_need(type(archive[\'unchanged\']) is bool,\'ARCHIVE\')\n    sr_image(archive[\'config_image_id\'],\'ARCHIVE\')\n    auth = archive[\'auth\']\n    sr_closed(auth,(\'profile\',\'source_fd\',\'wrapper\',\'target\',\'platform_manifest\',\'config\',\'layers\',\'legacy_manifest\'),\'ARCHIVE\')\n    profile = auth[\'profile\']; sr_need(profile in (\'LEGACY_CONFIG\',\'OCI_MANIFEST\',\'OCI_INDEX\'),\'ARCHIVE\')\n    sr_file_proof(auth[\'source_fd\'],archive)\n    for name in (\'wrapper\',\'legacy_manifest\'):\n        if auth[name] is not None: sr_need(type(auth[name]) is dict and type(auth[name].get(\'bytes\')) is int and auth[name][\'bytes\'] <= archive[\'bytes\'],\'ARCHIVE\')\n    for name in (\'target\',\'platform_manifest\'):\n        if auth[name] is not None:\n            sr_need(type(auth[name]) is dict and type(auth[name].get(\'blob\')) is dict and\n                    type(auth[name][\'blob\'].get(\'bytes\')) is int and auth[name][\'blob\'][\'bytes\'] <= archive[\'bytes\'],\'ARCHIVE\')\n    _raw,legacy = sr_archive_blob(auth[\'legacy_manifest\'],\'manifest.json\')\n    sr_need(type(legacy) is list and len(legacy) == 1 and type(legacy[0]) is dict,\'ARCHIVE\')\n    legacy = legacy[0]; config_path = sr_tar_path(legacy.get(\'Config\'))\n    layer_paths = legacy.get(\'Layers\'); sr_need(type(layer_paths) is list and 1 <= len(layer_paths) <= SR_LAYER_MAX,\'ARCHIVE\')\n    for path in layer_paths: sr_tar_path(path)\n    sr_need(legacy.get(\'LayerSources\') is None or type(legacy[\'LayerSources\']) is dict and not legacy[\'LayerSources\'],\'ARCHIVE\')\n    if legacy.get(\'RepoTags\') is not None:\n        sr_need(type(legacy[\'RepoTags\']) is list and len(legacy[\'RepoTags\']) <= 4096,\'ARCHIVE\')\n        for tag in legacy[\'RepoTags\']: sr_text(tag,4096,\'ARCHIVE\')\n    proof = auth[\'config\']; sr_closed(proof,(\'descriptor\',\'canonical\',\'consumer\',\'data_b64\'),\'ARCHIVE\')\n    canonical = sr_archive_member(proof[\'canonical\'],SR_CONFIG_MAX)\n    consumer = sr_archive_member(proof[\'consumer\'],SR_CONFIG_MAX)\n    raw = sr_b64(proof[\'data_b64\'],SR_CONFIG_MAX,\'ARCHIVE\')\n    config_id = \'sha256:\'+sr_digest(raw)\n    sr_need(config_id == archive[\'config_image_id\'] and len(raw) == canonical[\'bytes\'] == consumer[\'bytes\'] and\n            len(raw) <= archive[\'bytes\'] and canonical[\'sha256\'] == consumer[\'sha256\'] == config_id[7:] and consumer[\'path\'] == config_path,\'ARCHIVE\')\n    config = sr_json(raw,SR_CONFIG_MAX)\n    sr_need(type(config) is dict and config.get(\'os\') == \'linux\' and config.get(\'architecture\') == \'amd64\' and\n            config.get(\'variant\',\'\') in (\'\',\'v1\') and type(config.get(\'rootfs\')) is dict and\n            config[\'rootfs\'].get(\'type\') == \'layers\',\'ARCHIVE\')\n    diff_ids = config[\'rootfs\'].get(\'diff_ids\'); sr_need(type(diff_ids) is list and len(diff_ids) == len(layer_paths),\'ARCHIVE\')\n    for value in diff_ids: sr_image(value,\'ARCHIVE\')\n    layers = auth[\'layers\']; sr_need(type(layers) is list and len(layers) == len(layer_paths),\'ARCHIVE\')\n    inspect_desc = image[\'inspect_descriptor\']\n    if proof[\'descriptor\'] is not None: sr_descriptor(proof[\'descriptor\'],SR_CONFIG_MEDIA,SR_CONFIG_MAX)\n    target_id = manifest_id = None\n    if profile == \'LEGACY_CONFIG\':\n        sr_need(archive[\'docker_id_kind\'] == \'CONFIG\' and docker_id == config_id and\n                archive[\'target_digest\'] is archive[\'platform_manifest_digest\'] is None and\n                auth[\'wrapper\'] is auth[\'target\'] is auth[\'platform_manifest\'] is None,\'ARCHIVE\')\n        if inspect_desc is None:\n            sr_need(proof[\'descriptor\'] is None and canonical == consumer,\'ARCHIVE\')\n        else:\n            desc = sr_descriptor(inspect_desc,SR_CONFIG_MEDIA,SR_CONFIG_MAX)\n            sr_need(proof[\'descriptor\'] == desc and desc[\'digest\'] == config_id and desc[\'bytes\'] == len(raw) and\n                    canonical[\'path\'] == \'blobs/sha256/\'+config_id[7:],\'ARCHIVE\')\n        expected_layers = None\n    else:\n        target_media = SR_INDEX_MEDIA if profile == \'OCI_INDEX\' else SR_MANIFEST_MEDIA\n        inspect_desc = sr_descriptor(inspect_desc,target_media,SR_MEMBER_MAX)\n        target_desc,target = sr_descriptor_blob(auth[\'target\'],target_media)\n        target_id = target_desc[\'digest\']\n        sr_need(target_desc == inspect_desc and target_id == docker_id == archive[\'target_digest\'] and\n                archive[\'docker_id_kind\'] == (\'INDEX\' if profile == \'OCI_INDEX\' else \'MANIFEST\'),\'ARCHIVE\')\n        _raw,wrapper = sr_archive_blob(auth[\'wrapper\'],\'index.json\')\n        sr_need(type(wrapper) is dict and type(wrapper.get(\'schemaVersion\')) is int and wrapper[\'schemaVersion\'] == 2 and\n                (\'mediaType\' not in wrapper or wrapper[\'mediaType\'] in SR_INDEX_MEDIA),\'ARCHIVE\')\n        entries = wrapper.get(\'manifests\'); sr_need(type(entries) is list and 1 <= len(entries) <= 200000 and all(type(x) is dict for x in entries),\'ARCHIVE\')\n        matches = [row for row in entries if row.get(\'digest\') == docker_id]\n        sr_need(len(matches) == 1 and sr_raw_descriptor(matches[0],target_media,SR_MEMBER_MAX) == target_desc,\'ARCHIVE\')\n        if profile == \'OCI_INDEX\':\n            entries = target.get(\'manifests\'); sr_need(type(entries) is list and 1 <= len(entries) <= 200000 and all(type(x) is dict for x in entries),\'ARCHIVE\')\n            matches = [row for row in entries if type(row.get(\'platform\')) is dict and row[\'platform\'].get(\'os\') == \'linux\' and\n                       row[\'platform\'].get(\'architecture\') == \'amd64\' and row[\'platform\'].get(\'variant\',\'\') in (\'\',\'v1\')]\n            sr_need(len(matches) == 1,\'ARCHIVE\')\n            manifest_desc,manifest = sr_descriptor_blob(auth[\'platform_manifest\'],SR_MANIFEST_MEDIA)\n            sr_need(sr_raw_descriptor(matches[0],SR_MANIFEST_MEDIA,SR_MEMBER_MAX) == manifest_desc,\'ARCHIVE\')\n        else:\n            sr_need(auth[\'platform_manifest\'] is None,\'ARCHIVE\'); manifest_desc,manifest = target_desc,target\n        manifest_id = manifest_desc[\'digest\']\n        sr_need(manifest_id == archive[\'platform_manifest_digest\'] and manifest_id != config_id and\n                (profile != \'OCI_INDEX\' or target_id not in (manifest_id,config_id)),\'ARCHIVE\')\n        config_desc = sr_raw_descriptor(manifest.get(\'config\'),SR_CONFIG_MEDIA,SR_CONFIG_MAX)\n        sr_need(proof[\'descriptor\'] == config_desc and config_desc[\'digest\'] == config_id and config_desc[\'bytes\'] == len(raw) and\n                canonical[\'path\'] == \'blobs/sha256/\'+config_id[7:],\'ARCHIVE\')\n        expected_layers = manifest.get(\'layers\')\n        sr_need(type(expected_layers) is list and len(expected_layers) == len(layers),\'ARCHIVE\')\n    for index,row in enumerate(layers):\n        sr_closed(row,(\'descriptor\',\'canonical\',\'consumer\',\'uncompressed_tar_proven\'),\'ARCHIVE\')\n        canonical = sr_archive_member(row[\'canonical\'],SR_ARCHIVE_MAX)\n        consumer = sr_archive_member(row[\'consumer\'],SR_ARCHIVE_MAX)\n        sr_need(consumer[\'path\'] == layer_paths[index] and canonical[\'sha256\'] == consumer[\'sha256\'] and\n                canonical[\'bytes\'] == consumer[\'bytes\'] and canonical[\'bytes\'] <= archive[\'bytes\'],\'ARCHIVE\')\n        if profile == \'LEGACY_CONFIG\':\n            sr_need(row[\'descriptor\'] is None and canonical == consumer and row[\'uncompressed_tar_proven\'] is True and\n                    \'sha256:\'+canonical[\'sha256\'] == diff_ids[index] and canonical[\'bytes\'] >= 1024 and\n                    canonical[\'bytes\'] % 512 == 0,\'ARCHIVE\')\n        else:\n            desc = sr_descriptor(row[\'descriptor\'],SR_LAYER_MEDIA)\n            sr_need(desc == sr_raw_descriptor(expected_layers[index],SR_LAYER_MEDIA) and\n                    canonical[\'path\'] == \'blobs/sha256/\'+desc[\'digest\'][7:] and\n                    desc[\'digest\'] == \'sha256:\'+canonical[\'sha256\'] and desc[\'bytes\'] == canonical[\'bytes\'] and\n                    row[\'uncompressed_tar_proven\'] is None,\'ARCHIVE\')\n    observed = [auth[\'legacy_manifest\'],proof[\'canonical\'],proof[\'consumer\']]\n    if auth[\'wrapper\'] is not None: observed.append(auth[\'wrapper\'])\n    for name in (\'target\',\'platform_manifest\'):\n        if auth[name] is not None: observed.append(auth[name][\'blob\'])\n    for row in layers: observed.extend((row[\'canonical\'],row[\'consumer\']))\n    members = {}\n    for row in observed:\n        signature = (row[\'sha256\'],row[\'bytes\'])\n        sr_need(row[\'path\'] not in members or members[row[\'path\']] == signature,\'ARCHIVE\')\n        members[row[\'path\']] = signature\n    # Even selected records alone must fit the actual complete outer TAR.\n    minimum = 1024+sum(512+512*((size+511)//512) for _sha,size in members.values())\n    sr_need(minimum <= archive[\'bytes\'],\'ARCHIVE\')\n    return {\'docker_image_id\':docker_id,\'docker_id_kind\':archive[\'docker_id_kind\'],\'archive_identity_profile\':profile,\n            \'config_image_id\':config_id,\'target_digest\':target_id,\'platform_manifest_digest\':manifest_id}\n\n\ndef validate_archive_auth(image, archive):\n    """One shared pure archive authority for owner pre-scan and final reducer."""\n    try:\n        sr_evidence_bound({\'image\':image,\'archive\':archive})\n        roles = sr_archive_roles(image,archive)\n        return {\'valid\':True,\'reason\':\'OK\',\'roles\':roles}\n    except Exception:\n        return {\'valid\':False,\'reason\':\'ARCHIVE_REJECTED\',\'roles\':None}\n\n\ndef sr_empty_summary():\n    return {\'schemaVersion\':2,\'scope\':SR_SCOPE,\'status\':\'ERROR\',\'category\':\'BOOTSTRAP\',\n            \'identities\':None,\'db\':None,\'coverage\':None,\'actual_exit\':None,\'findings\':None,\'cleanup\':False}\n\n\ndef sr_finding(row):\n    sr_need(type(row) is dict,\'JSON\')\n    advisory = sr_text(row.get(\'VulnerabilityID\'),128,\'JSON\')\n    sr_need(re.fullmatch(\'[A-Za-z0-9][A-Za-z0-9._:+-]*\',advisory) is not None,\'JSON\')\n    package = sr_name(row.get(\'PkgName\'),\'JSON\'); installed = sr_version(row.get(\'InstalledVersion\'),\'JSON\')\n    fixed = sr_version(row.get(\'FixedVersion\',\'\'),\'JSON\',True)\n    severity = row.get(\'Severity\'); sr_need(severity in (\'HIGH\',\'CRITICAL\'),\'JSON\')\n    status = row.get(\'Status\')\n    sr_need(status is None or type(status) is str and status in (\'\',\'unknown\',\'affected\',\'fixed\',\'under_investigation\',\'will_not_fix\',\'fix_deferred\',\'end_of_life\'),\'JSON\')\n    return {\'id\':advisory,\'pkg\':package,\'installed\':installed,\'fixed\':fixed,\'severity\':severity,\'status\':status}\n\n\ndef sr_validate_summary(value):\n    sr_closed(value,(\'schemaVersion\',\'scope\',\'status\',\'category\',\'identities\',\'db\',\'coverage\',\'actual_exit\',\'findings\',\'cleanup\'),\'JSON\')\n    sr_int(value[\'schemaVersion\'],2,2,\'JSON\'); sr_need(value[\'scope\'] == SR_SCOPE and value[\'status\'] in (\'PASS\',\'FINDINGS\',\'ERROR\') and type(value[\'cleanup\']) is bool,\'JSON\')\n    if value[\'actual_exit\'] is not None: sr_int(value[\'actual_exit\'],0,255,\'JSON\')\n    ids = value[\'identities\']\n    if ids is not None:\n        sr_closed(ids,SR_ID_KEYS,\'JSON\')\n        for key,item in ids.items():\n            if item is None: continue\n            if key == \'source_head\': sr_need(type(item) is str and re.fullmatch(\'[0-9a-f]{40}\',item) is not None,\'JSON\')\n            elif key == \'docker_id_kind\': sr_need(item in (\'CONFIG\',\'MANIFEST\',\'INDEX\'),\'JSON\')\n            elif key == \'archive_identity_profile\': sr_need(item in (\'LEGACY_CONFIG\',\'OCI_MANIFEST\',\'OCI_INDEX\'),\'JSON\')\n            elif key == \'trivy_report_image_id_domain\': sr_need(item == \'CONFIG\',\'JSON\')\n            elif key == \'metadata_image_key\': sr_need(item in (\'containerimage.config.digest\',\'containerimage.digest\'),\'JSON\')\n            elif key == \'metadata_image_role\': sr_need(item in (\'CONFIG\',\'DOCKER\'),\'JSON\')\n            elif key in (\'source_sha256\',\'archive_sha256\',\'report_sha256\',\'version_sha256\',\'witness_sha256\',\'build_metadata_sha256\'): sr_hash(item,\'JSON\')\n            else: sr_image(item,\'JSON\')\n    db = value[\'db\']\n    if db is not None:\n        sr_closed(db,(\'scanner_version\',\'schema_version\',\'updated_at\',\'downloaded_at\',\'next_update\',\'fresh_cache\',\'download_in_scan_window\'),\'JSON\')\n        sr_need(db[\'scanner_version\'] == \'0.57.1\' and db[\'fresh_cache\'] is db[\'download_in_scan_window\'] is True,\'JSON\')\n        sr_int(db[\'schema_version\'],2,2,\'JSON\')\n        for key in (\'updated_at\',\'downloaded_at\',\'next_update\'): sr_timestamp(db[key],\'JSON\')\n        sr_need(sr_timestamp(db[\'updated_at\'],\'JSON\') < sr_timestamp(db[\'next_update\'],\'JSON\'),\'JSON\')\n    coverage = value[\'coverage\']\n    if coverage is not None:\n        sr_closed(coverage,(\'report_schema_version\',\'os\',\'python\',\'rust\',\'node\',\'limits\'),\'JSON\')\n        sr_int(coverage[\'report_schema_version\'],2,2,\'JSON\'); sr_need(coverage[\'limits\'] == SR_LIMITS,\'JSON\')\n        osdata = coverage[\'os\']; sr_closed(osdata,(\'family\',\'name\',\'supported_by_tagged_scanner\',\'eosl\',\'package_count\',\'inventory_sha256\'),\'JSON\')\n        sr_need(osdata[\'family\'] == \'debian\' and type(osdata[\'name\']) is str and re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',osdata[\'name\']) is not None and\n                osdata[\'supported_by_tagged_scanner\'] is True and osdata[\'eosl\'] is False,\'JSON\')\n        sr_int(osdata[\'package_count\'],1,200000,\'JSON\'); sr_hash(osdata[\'inventory_sha256\'],\'JSON\')\n        py = coverage[\'python\']; sr_closed(py,(\'metadata_files\',\'installed_pairs\',\'venv_pairs\',\'lock_runtime_pairs\',\'reported_pairs\',\'inventory_sha256\',\'venv_inventory_sha256\',\'lock_inventory_sha256\'),\'JSON\')\n        for key in (\'metadata_files\',\'installed_pairs\',\'venv_pairs\',\'lock_runtime_pairs\',\'reported_pairs\'): sr_int(py[key],1,200000,\'JSON\')\n        sr_need(py[\'lock_runtime_pairs\'] <= py[\'venv_pairs\'] <= py[\'installed_pairs\'] == py[\'reported_pairs\'] <= py[\'metadata_files\'],\'JSON\')\n        for key in (\'inventory_sha256\',\'venv_inventory_sha256\',\'lock_inventory_sha256\'): sr_hash(py[key],\'JSON\')\n        sr_closed(coverage[\'rust\'],(\'uv\',\'uvx\'),\'JSON\')\n        for row in coverage[\'rust\'].values():\n            sr_closed(row,(\'binary_sha256\',\'package_count\',\'inventory_sha256\'),\'JSON\'); sr_hash(row[\'binary_sha256\'],\'JSON\')\n            sr_hash(row[\'inventory_sha256\'],\'JSON\'); sr_int(row[\'package_count\'],1,200000,\'JSON\')\n        node = coverage[\'node\']; sr_closed(node,(\'applicability\',\'metadata_files\',\'installed_pairs\',\'reported_pairs\',\'inventory_sha256\'),\'JSON\')\n        sr_need(node[\'applicability\'] in (\'ABSENT\',\'PRESENT\'),\'JSON\')\n        for key in (\'metadata_files\',\'installed_pairs\',\'reported_pairs\'): sr_int(node[key],0,200000,\'JSON\')\n        sr_hash(node[\'inventory_sha256\'],\'JSON\'); sr_need(node[\'installed_pairs\'] == node[\'reported_pairs\'] <= node[\'metadata_files\'],\'JSON\')\n        sr_need(node[\'installed_pairs\'] > 0 if node[\'applicability\'] == \'PRESENT\' else node[\'metadata_files\'] == node[\'installed_pairs\'] == 0,\'JSON\')\n    findings = value[\'findings\']\n    if findings is not None:\n        sr_need(type(findings) is list and len(findings) <= 8192,\'JSON\')\n        for row in findings:\n            sr_closed(row,(\'id\',\'pkg\',\'installed\',\'fixed\',\'severity\',\'status\'),\'JSON\')\n            mapped = sr_finding({\'VulnerabilityID\':row[\'id\'],\'PkgName\':row[\'pkg\'],\'InstalledVersion\':row[\'installed\'],\n                                 \'FixedVersion\':row[\'fixed\'],\'Severity\':row[\'severity\'],\'Status\':row[\'status\']})\n            sr_need(mapped == row,\'JSON\')\n    if value[\'status\'] == \'ERROR\': sr_need(value[\'category\'] in SR_ERRORS,\'JSON\')\n    else:\n        sr_need(ids is not None and all(item is not None for key,item in ids.items() if key not in (\'sdk_target_digest\',\'sdk_platform_manifest_digest\')) and db is not None and coverage is not None and\n                findings is not None and value[\'cleanup\'] is True,\'JSON\')\n        sr_need(ids[\'docker_image_id\'] != ids[\'scanner_docker_image_id\'] and\n                ids[\'trivy_report_image_id\'] == ids[\'sdk_config_image_id\'] and ids[\'iid_image_id\'] == ids[\'metadata_image_id\'],\'JSON\')\n        if ids[\'archive_identity_profile\'] == \'LEGACY_CONFIG\':\n            sr_need(ids[\'docker_id_kind\'] == \'CONFIG\' and ids[\'docker_image_id\'] == ids[\'sdk_config_image_id\'] and\n                    ids[\'sdk_target_digest\'] is ids[\'sdk_platform_manifest_digest\'] is None,\'JSON\')\n        else:\n            sr_need(ids[\'sdk_target_digest\'] is not None and ids[\'sdk_platform_manifest_digest\'] is not None and\n                    ids[\'docker_image_id\'] == ids[\'sdk_target_digest\'] and ids[\'sdk_platform_manifest_digest\'] != ids[\'sdk_config_image_id\'],\'JSON\')\n            if ids[\'archive_identity_profile\'] == \'OCI_MANIFEST\':\n                sr_need(ids[\'docker_id_kind\'] == \'MANIFEST\' and ids[\'sdk_target_digest\'] == ids[\'sdk_platform_manifest_digest\'],\'JSON\')\n            else:\n                sr_need(ids[\'docker_id_kind\'] == \'INDEX\' and ids[\'sdk_target_digest\'] not in\n                        (ids[\'sdk_platform_manifest_digest\'],ids[\'sdk_config_image_id\']),\'JSON\')\n        expected_role = \'CONFIG\' if ids[\'metadata_image_key\'] == \'containerimage.config.digest\' else \'DOCKER\'\n        sr_need(ids[\'metadata_image_role\'] == expected_role and ids[\'metadata_image_id\'] ==\n                (ids[\'sdk_config_image_id\'] if expected_role == \'CONFIG\' else ids[\'docker_image_id\']),\'JSON\')\n        if value[\'status\'] == \'PASS\': sr_need(value[\'category\'] == \'OK\' and value[\'actual_exit\'] == 0 and findings == [],\'JSON\')\n        else: sr_need(value[\'category\'] == \'HIGH_CRITICAL\' and value[\'actual_exit\'] == 1 and len(findings) > 0,\'JSON\')\n\n\ndef validate_safe_summary(raw):\n    """Return only a validated closed safe DTO, or fixed invalid/null."""\n    try:\n        value = sr_json(raw,SR_SUMMARY_MAX); sr_validate_summary(value)\n        return {\'valid\':True,\'report\':value}\n    except Exception:\n        return {\'valid\':False,\'report\':None}\n\n\ndef sr_finish(out):\n    try:\n        sr_validate_summary(out)\n        if len(sr_canonical(out)) <= SR_SUMMARY_MAX: return out\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = \'OVERFLOW\'; out[\'findings\'] = None\n        sr_validate_summary(out)\n        if len(sr_canonical(out)) <= SR_SUMMARY_MAX: return out\n    except Exception:\n        pass\n    empty = sr_empty_summary(); empty[\'category\'] = \'INTERNAL\'\n    return empty\n\n\ndef validate_scan_evidence(evidence, report_raw, version_raw):\n    """Total pure reducer; ERROR outranks findings and no raw field is reflected."""\n    out = sr_empty_summary()\n    try:\n        sr_closed(evidence,(\'schemaVersion\',\'source\',\'build\',\'image\',\'archive\',\'scanner\',\'witness\',\'inputs\',\'final\',\'error_codes\'),\'BOOTSTRAP\')\n        sr_evidence_bound(evidence)\n        sr_int(evidence[\'schemaVersion\'],2,2,\'BOOTSTRAP\')\n        errors = evidence[\'error_codes\']; sr_need(type(errors) is list and len(errors) <= len(SR_ERRORS) and all(type(x) is str and x in SR_ERRORS for x in errors),\'BOOTSTRAP\')\n        scanner = evidence[\'scanner\']\n        if type(scanner) is dict and type(scanner.get(\'scan_exit\')) is int and 0 <= scanner[\'scan_exit\'] <= 255: out[\'actual_exit\'] = scanner[\'scan_exit\']\n        if errors: raise SRRejected(next(code for code in SR_ERRORS if code in errors))\n        final = evidence[\'final\']; sr_closed(final,(\'archive_unchanged\',\'cancelled\',\'containers_removed\',\'image_unchanged\',\'owned_cli_drain\',\'owned_image_removed\',\'private_context_removed\',\'source_unchanged\',\'uncertain\'),\'CLEANUP\')\n        sr_need(all(type(x) is bool for x in final.values()),\'CLEANUP\')\n        sr_need(not final[\'cancelled\'],\'CANCELLED\')\n        sr_need(not final[\'uncertain\'] and all(final[k] for k in (\'owned_cli_drain\',\'containers_removed\',\'owned_image_removed\',\'private_context_removed\')),\'CLEANUP\'); out[\'cleanup\'] = True\n        sr_need(final[\'source_unchanged\'],\'SOURCE\'); sr_need(final[\'image_unchanged\'],\'LINEAGE\'); sr_need(final[\'archive_unchanged\'],\'ARCHIVE\')\n        source = evidence[\'source\']; sr_closed(source,(\'before\',\'after\',\'context_sha256\',\'head\'),\'SOURCE\')\n        sr_need(type(source[\'head\']) is str and re.fullmatch(\'[0-9a-f]{40}\',source[\'head\']) is not None,\'SOURCE\')\n        for values in (source[\'before\'],source[\'after\']):\n            sr_need(type(values) is dict and SR_REQUIRED_SOURCE <= set(values) and len(values) <= 4096,\'SOURCE\')\n            for path,row in values.items():\n                sr_path(path,\'SOURCE\',False); sr_closed(row,(\'sha256\',\'bytes\'),\'SOURCE\'); sr_hash(row[\'sha256\'],\'SOURCE\'); sr_int(row[\'bytes\'],0,16777216,\'SOURCE\')\n        sr_need(sr_canonical(source[\'before\']) == sr_canonical(source[\'after\']) and\n                sr_digest(sr_canonical(source[\'before\'])) == sr_hash(source[\'context_sha256\'],\'SOURCE\'),\'SOURCE\')\n        image = evidence[\'image\']; archive = evidence[\'archive\']\n        auth_result = validate_archive_auth(image,archive)\n        sr_need(auth_result[\'valid\'] is True,\'ARCHIVE\'); roles = auth_result[\'roles\']\n        sr_need(archive[\'unchanged\'] is True,\'ARCHIVE\')\n        build = evidence[\'build\']; sr_closed(build,(\'actual_exit\',\'metadata_sha256\',\'iid_image_id\',\'metadata_image_id\',\n                                                   \'metadata_image_key\',\'metadata_image_role\',\'uv\'),\'BUILD\')\n        sr_int(build[\'actual_exit\'],0,0,\'BUILD\'); sr_hash(build[\'metadata_sha256\'],\'BUILD\')\n        sr_image(build[\'iid_image_id\'],\'LINEAGE\'); sr_image(build[\'metadata_image_id\'],\'LINEAGE\')\n        sr_need(build[\'metadata_image_key\'] in (\'containerimage.config.digest\',\'containerimage.digest\'),\'LINEAGE\')\n        expected_role = \'CONFIG\' if build[\'metadata_image_key\'] == \'containerimage.config.digest\' else \'DOCKER\'\n        sr_need(build[\'metadata_image_role\'] == expected_role and build[\'metadata_image_id\'] ==\n                (roles[\'config_image_id\'] if expected_role == \'CONFIG\' else image[\'id\']) and\n                build[\'iid_image_id\'] == build[\'metadata_image_id\'],\'LINEAGE\')\n        uv = build[\'uv\']; sr_closed(uv,(\'actual_build_material_join\',\'index_digest\',\'index_sha256\',\'manifest_sha256\',\'material_digest\',\'material_uri\',\'platform\',\'platform_manifest_digest\',\'reference\'),\'LINEAGE\')\n        sr_need(uv[\'actual_build_material_join\'] is True and uv[\'reference\'] == \'ghcr.io/astral-sh/uv:0.12.8\' and uv[\'platform\'] == \'linux/amd64\',\'LINEAGE\')\n        sr_text(uv[\'material_uri\'],4096,\'LINEAGE\')\n        sr_need(not any(ord(c) < 32 or ord(c) == 127 for c in uv[\'material_uri\']),\'LINEAGE\')\n        sr_image(uv[\'material_digest\'],\'LINEAGE\'); sr_image(uv[\'platform_manifest_digest\'],\'LINEAGE\'); sr_hash(uv[\'manifest_sha256\'],\'LINEAGE\')\n        sr_need(uv[\'manifest_sha256\'] == uv[\'platform_manifest_digest\'][7:],\'LINEAGE\')\n        if uv[\'index_digest\'] is None:\n            sr_need(uv[\'index_sha256\'] is None and uv[\'material_digest\'] == uv[\'platform_manifest_digest\'],\'LINEAGE\')\n        else:\n            sr_image(uv[\'index_digest\'],\'LINEAGE\'); sr_need(sr_hash(uv[\'index_sha256\'],\'LINEAGE\') == uv[\'index_digest\'][7:] and uv[\'material_digest\'] == uv[\'index_digest\'],\'LINEAGE\')\n        sr_closed(scanner,(\'config_sha256\',\'db_download_scan_only\',\'empty_cache_before\',\'help_flags\',\'help_sha256\',\'ignore_sha256\',\'image_id\',\'same_cache\',\'scan_exit\',\'scan_utc\',\'version_after_exit\',\'version_after_utc\',\'version_before_b64\',\'version_before_exit\'),\'SCANNER\')\n        sr_image(scanner[\'image_id\'],\'TOOL\'); sr_need(scanner[\'image_id\'] != image[\'id\'],\'TOOL\'); sr_hash(scanner[\'help_sha256\'],\'TOOL\')\n        sr_need(type(scanner[\'help_flags\']) is list and 1 <= len(scanner[\'help_flags\']) <= 128 and\n                all(type(x) is str and 0 < len(x) <= 128 and\n                    not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in x)\n                    for x in scanner[\'help_flags\']) and\n                len(scanner[\'help_flags\']) == len(set(scanner[\'help_flags\'])) and\n                SR_HELP_FLAGS <= set(scanner[\'help_flags\']),\'TOOL\')\n        sr_need(scanner[\'config_sha256\'] == sr_digest(b\'{}\\n\') and scanner[\'ignore_sha256\'] == sr_digest(b\'\') and scanner[\'db_download_scan_only\'] is True,\'SCANNER\')\n        sr_need(scanner[\'empty_cache_before\'] is scanner[\'same_cache\'] is True,\'DB\')\n        sr_int(scanner[\'version_before_exit\'],0,0,\'TOOL\'); sr_int(scanner[\'version_after_exit\'],0,0,\'DB\')\n        before = sr_json(sr_b64(scanner[\'version_before_b64\'],SR_VERSION_MAX,\'DB\'),SR_VERSION_MAX)\n        sr_need(type(before) is dict and before.get(\'Version\') == \'0.57.1\',\'TOOL\')\n        sr_need(\'VulnerabilityDB\' not in before or before[\'VulnerabilityDB\'] is None,\'DB\')\n        scan_time = sr_timestamp(scanner[\'scan_utc\'],\'DB\'); after_time = sr_timestamp(scanner[\'version_after_utc\'],\'DB\'); sr_need(scan_time <= after_time,\'DB\')\n        sr_int(scanner[\'scan_exit\'],0,255,\'EXIT\')\n        witness = evidence[\'witness\']; sr_closed(witness,(\'complete\',\'image_id\',\'member_count\',\'node\',\'os_release\',\'python\',\'rootfs_bytes\',\'rootfs_sha256\',\'uv\',\'uvx\'),\'WITNESS\')\n        sr_need(witness[\'complete\'] is True and witness[\'image_id\'] == image[\'id\'],\'WITNESS\'); sr_int(witness[\'member_count\'],1,200000,\'WITNESS\')\n        sr_int(witness[\'rootfs_bytes\'],1,4294967296,\'WITNESS\'); sr_hash(witness[\'rootfs_sha256\'],\'WITNESS\')\n        sr_need(type(report_raw) is bytes and 0 < len(report_raw) <= SR_RAW_MAX and type(version_raw) is bytes and 0 < len(version_raw) <= SR_VERSION_MAX,\'JSON\')\n        out[\'identities\'] = {\'source_head\':source[\'head\'],\'source_sha256\':source[\'context_sha256\'],\n            \'docker_image_id\':image[\'id\'],\'docker_id_kind\':roles[\'docker_id_kind\'],\'archive_identity_profile\':roles[\'archive_identity_profile\'],\n            \'sdk_target_digest\':roles[\'target_digest\'],\'sdk_platform_manifest_digest\':roles[\'platform_manifest_digest\'],\n            \'sdk_config_image_id\':roles[\'config_image_id\'],\'trivy_report_image_id\':None,\'trivy_report_image_id_domain\':\'CONFIG\',\n            \'iid_image_id\':build[\'iid_image_id\'],\'metadata_image_id\':build[\'metadata_image_id\'],\n            \'metadata_image_key\':build[\'metadata_image_key\'],\'metadata_image_role\':build[\'metadata_image_role\'],\n            \'archive_sha256\':archive[\'sha256\'],\'scanner_docker_image_id\':scanner[\'image_id\'],\'report_sha256\':sr_digest(report_raw),\n            \'version_sha256\':sr_digest(version_raw),\'witness_sha256\':sr_digest(sr_canonical(evidence)),\n            \'build_metadata_sha256\':build[\'metadata_sha256\'],\'uv_material_digest\':uv[\'material_digest\'],\'uv_platform_manifest_digest\':uv[\'platform_manifest_digest\']}\n        version = sr_json(version_raw,SR_VERSION_MAX); sr_need(type(version) is dict and version.get(\'Version\') == \'0.57.1\',\'TOOL\')\n        db = version.get(\'VulnerabilityDB\'); sr_need(type(db) is dict,\'DB\'); sr_int(db.get(\'Version\'),2,2,\'DB\')\n        for key in (\'UpdatedAt\',\'DownloadedAt\',\'NextUpdate\'): sr_timestamp(db.get(key),\'DB\')\n        sr_need(scan_time <= sr_timestamp(db[\'DownloadedAt\'],\'DB\') <= after_time and sr_timestamp(db[\'UpdatedAt\'],\'DB\') < sr_timestamp(db[\'NextUpdate\'],\'DB\'),\'DB\')\n        out[\'db\'] = {\'scanner_version\':\'0.57.1\',\'schema_version\':2,\'updated_at\':db[\'UpdatedAt\'],\'downloaded_at\':db[\'DownloadedAt\'],\'next_update\':db[\'NextUpdate\'],\'fresh_cache\':True,\'download_in_scan_window\':True}\n        report = sr_json(report_raw,SR_RAW_MAX); sr_need(type(report) is dict,\'JSON\'); sr_int(report.get(\'SchemaVersion\'),2,2,\'JSON\')\n        metadata = report.get(\'Metadata\'); sr_need(type(metadata) is dict and metadata.get(\'ImageID\') == roles[\'config_image_id\'],\'SCANNER\')\n        out[\'identities\'][\'trivy_report_image_id\'] = metadata[\'ImageID\']\n        osmeta = metadata.get(\'OS\'); sr_need(type(osmeta) is dict and osmeta.get(\'Family\') == \'debian\',\'OS\')\n        osname = sr_text(osmeta.get(\'Name\'),32,\'OS\'); sr_need(re.fullmatch(r\'[0-9]+(?:\\.[0-9]+)*\',osname) is not None,\'OS\')\n        major = sr_os_release(witness[\'os_release\']); sr_need(major == osname.split(\'.\')[0] and major in SR_DEBIAN_EOL and scan_time < sr_timestamp(SR_DEBIAN_EOL[major],\'OS\'),\'OS\')\n        sr_need(\'EOSL\' not in osmeta or type(osmeta[\'EOSL\']) is bool and osmeta[\'EOSL\'] is False,\'OS\')\n        sr_need(\'extended\' not in osmeta or osmeta[\'extended\'] is False,\'OS\')\n        results = report.get(\'Results\'); sr_need(type(results) is list and results,\'JSON\')\n        inventories = {\'os\':set(),\'python\':set(),\'node\':set(),\'uv\':set(),\'uvx\':set()}; aliases = {}; rust_rows = {}\n        for role in (\'uv\',\'uvx\'):\n            row = witness[role]; sr_closed(row,(\'requested_path\',\'resolved_path\',\'aliases\',\'sha256\',\'bytes\',\'mode\',\'executable\'),\'RUST\')\n            sr_need(row[\'requested_path\'] == \'/bin/\'+role and row[\'executable\'] is True,\'RUST\'); sr_path(row[\'resolved_path\'],\'RUST\')\n            sr_int(row[\'bytes\'],1,268435456,\'RUST\'); mode = sr_int(row[\'mode\'],0,0o7777,\'RUST\'); sr_need(mode & 0o111 and not mode & 0o022,\'RUST\'); sr_hash(row[\'sha256\'],\'RUST\')\n            sr_need(type(row[\'aliases\']) is list and 1 <= len(row[\'aliases\']) <= 32 and len(row[\'aliases\']) == len(set(row[\'aliases\'])),\'RUST\')\n            for path in row[\'aliases\']: sr_path(path,\'RUST\')\n            sr_need(row[\'requested_path\'] in row[\'aliases\'] and row[\'resolved_path\'] in row[\'aliases\'],\'RUST\')\n            aliases[role] = set(row[\'aliases\']); rust_rows[role] = row\n        sr_need(aliases[\'uv\'].isdisjoint(aliases[\'uvx\']),\'RUST\')\n        findings = []; seen_rust = set()\n        for result in results:\n            sr_need(type(result) is dict,\'JSON\'); kind = result.get(\'Type\'); cls = result.get(\'Class\')\n            sr_text(kind,128,\'JSON\'); sr_text(cls,128,\'JSON\'); sr_text(result.get(\'Target\'),4096,\'JSON\',True)\n            code = \'OS\' if cls == \'os-pkgs\' else \'PYTHON\' if kind == \'python-pkg\' else \'RUST\' if kind == \'rustbinary\' else \'NODE\' if kind == \'node-pkg\' else \'JSON\'\n            packages = sr_pairs(result.get(\'Packages\',[]),code,kind == \'python-pkg\')\n            if cls == \'os-pkgs\':\n                sr_need(kind == \'debian\' and packages,\'OS\'); inventories[\'os\'].update(packages)\n            elif kind in (\'python-pkg\',\'node-pkg\',\'rustbinary\'):\n                sr_need(cls == \'lang-pkgs\',code)\n                if kind == \'python-pkg\': inventories[\'python\'].update(packages)\n                elif kind == \'node-pkg\': inventories[\'node\'].update(packages)\n                else:\n                    target = \'/\'+result[\'Target\'].lstrip(\'/\'); sr_path(target,\'RUST\')\n                    matching = [role for role in aliases if target in aliases[role]]\n                    sr_need(len(matching) <= 1,\'RUST\')\n                    if matching:\n                        role = matching[0]; sr_need(role not in seen_rust and packages,\'RUST\'); seen_rust.add(role); inventories[role] = packages\n            rows = result.get(\'Vulnerabilities\',[]); sr_need(type(rows) is list,\'JSON\')\n            for row in rows:\n                finding = sr_finding(row)\n                sr_need((sr_name(finding[\'pkg\'],\'JSON\',kind == \'python-pkg\'),finding[\'installed\']) in packages,\'JSON\')\n                findings.append(finding); sr_need(len(findings) <= 8192,\'OVERFLOW\')\n        sr_need(inventories[\'os\'] and inventories[\'python\'] and seen_rust == {\'uv\',\'uvx\'},\'OS\' if not inventories[\'os\'] else \'RUST\' if seen_rust != {\'uv\',\'uvx\'} else \'PYTHON\')\n        py = witness[\'python\']; sr_closed(py,(\'implementation\',\'metadata\',\'platform\',\'venv\',\'version\',\'version_metadata_sha256\'),\'PYTHON\')\n        sr_need(py[\'implementation\'] == \'cpython\' and py[\'venv\'] == SR_VENV and py[\'platform\'] == {\'os_name\':\'posix\',\'sys_platform\':\'linux\',\'platform_system\':\'Linux\',\'platform_machine\':\'x86_64\',\'platform_python_implementation\':\'CPython\'},\'PYTHON\')\n        sr_hash(py[\'version_metadata_sha256\'],\'PYTHON\'); python_version = sr_numeric_version(py[\'version\']); sr_need(len(python_version) == 3,\'PYTHON\')\n        installed,venv = sr_metadata_rows(py[\'metadata\']); sr_need(installed == inventories[\'python\'],\'PYTHON\')\n        inputs = evidence[\'inputs\']; sr_closed(inputs,(\'no_dev\',\'pyproject_b64\',\'selected_extras\',\'uv_lock_b64\'),\'PYTHON\')\n        sr_need(inputs[\'no_dev\'] is True and inputs[\'selected_extras\'] == [] and type(inputs[\'selected_extras\']) is list,\'PYTHON\')\n        lock_raw = sr_b64(inputs[\'uv_lock_b64\'],SR_MEMBER_MAX,\'PYTHON\'); project_raw = sr_b64(inputs[\'pyproject_b64\'],SR_MEMBER_MAX,\'PYTHON\')\n        for path,raw in ((SR_LOCK,lock_raw),(SR_PROJECT,project_raw)):\n            sr_need(source[\'before\'][path] == {\'sha256\':sr_digest(raw),\'bytes\':len(raw)},\'SOURCE\')\n        runtime = sr_runtime_lock(lock_raw,project_raw,py[\'version\']); sr_need(runtime and runtime <= venv,\'PYTHON\')\n        node_pairs = sr_node_rows(witness[\'node\']); sr_need(node_pairs == inventories[\'node\'],\'NODE\')\n        out[\'coverage\'] = {\'report_schema_version\':2,\n            \'os\':{\'family\':\'debian\',\'name\':osname,\'supported_by_tagged_scanner\':True,\'eosl\':False,\'package_count\':len(inventories[\'os\']),\'inventory_sha256\':sr_inventory_hash(inventories[\'os\'])},\n            \'python\':{\'metadata_files\':len(py[\'metadata\']),\'installed_pairs\':len(installed),\'venv_pairs\':len(venv),\'lock_runtime_pairs\':len(runtime),\'reported_pairs\':len(inventories[\'python\']),\'inventory_sha256\':sr_inventory_hash(installed),\'venv_inventory_sha256\':sr_inventory_hash(venv),\'lock_inventory_sha256\':sr_inventory_hash(runtime)},\n            \'rust\':{role:{\'binary_sha256\':rust_rows[role][\'sha256\'],\'package_count\':len(inventories[role]),\'inventory_sha256\':sr_inventory_hash(inventories[role])}for role in (\'uv\',\'uvx\')},\n            \'node\':{\'applicability\':witness[\'node\'][\'applicability\'],\'metadata_files\':len(witness[\'node\'][\'metadata\']),\'installed_pairs\':len(node_pairs),\'reported_pairs\':len(inventories[\'node\']),\'inventory_sha256\':sr_inventory_hash(node_pairs)},\'limits\':copy.deepcopy(SR_LIMITS)}\n        out[\'findings\'] = findings\n        if scanner[\'scan_exit\'] == 0 and not findings: out[\'status\'] = \'PASS\'; out[\'category\'] = \'OK\'\n        elif scanner[\'scan_exit\'] == 1 and findings: out[\'status\'] = \'FINDINGS\'; out[\'category\'] = \'HIGH_CRITICAL\'\n        else: raise SRRejected(\'EXIT\')\n    except SRRejected as error:\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = error.code\n    except Exception:\n        out[\'status\'] = \'ERROR\'; out[\'category\'] = \'INTERNAL\'\n    return sr_finish(out)\n\n\ndef sr_control_archive(evidence, report, profile=\'LEGACY_CONFIG\'):\n    """Synthetic owner observations only; hosted owner controls prove actual I/O."""\n    def desc(raw, media): return {\'media_type\':media,\'digest\':\'sha256:\'+sr_digest(raw),\'bytes\':len(raw)}\n    def member(path, raw): return {\'path\':path,\'sha256\':sr_digest(raw),\'bytes\':len(raw)}\n    def blob(path, raw): return {**member(path,raw),\'data_b64\':base64.b64encode(raw).decode(\'ascii\')}\n    def pair(raw, media):\n        descriptor = desc(raw,media)\n        return {\'descriptor\':descriptor,\'blob\':blob(\'blobs/sha256/\'+descriptor[\'digest\'][7:],raw)}\n    def wire(descriptor): return {\'mediaType\':descriptor[\'media_type\'],\'digest\':descriptor[\'digest\'],\'size\':descriptor[\'bytes\']}\n    layer = b\'\\0\'*1024\n    config = sr_canonical({\'os\':\'linux\',\'architecture\':\'amd64\',\'rootfs\':{\'type\':\'layers\',\'diff_ids\':[\'sha256:\'+sr_digest(layer)]}})\n    config_id = \'sha256:\'+sr_digest(config)\n    config_path,layer_path = \'consumer/config.payload\',\'consumer/layer.payload\'\n    legacy = sr_canonical([{\'Config\':config_path,\'RepoTags\':[],\'Layers\':[layer_path]}])\n    config_proof = {\'descriptor\':None,\'canonical\':member(config_path,config),\'consumer\':member(config_path,config),\n                    \'data_b64\':base64.b64encode(config).decode(\'ascii\')}\n    layer_proof = {\'descriptor\':None,\'canonical\':member(layer_path,layer),\'consumer\':member(layer_path,layer),\'uncompressed_tar_proven\':True}\n    ident = {\'device\':1,\'inode\':17,\'uid\':1000,\'gid\':1000,\'mode\':0o600,\'links\':1,\'bytes\':16384,\'mtime_ns\':1,\'ctime_ns\':1}\n    fd = {name:copy.deepcopy(ident) for name in (\'fd_before\',\'path_before\',\'fd_after\',\'path_after\')}\n    fd.update(sha256_before=\'6\'*64,sha256_after=\'6\'*64,held_one_fd=True,complete_outer_tar=True)\n    auth = {\'profile\':profile,\'source_fd\':fd,\'wrapper\':None,\'target\':None,\'platform_manifest\':None,\n            \'config\':config_proof,\'layers\':[layer_proof],\'legacy_manifest\':blob(\'manifest.json\',legacy)}\n    image = {\'id\':config_id,\'inspect_descriptor\':None,\'os\':\'linux\',\'architecture\':\'amd64\',\'variant\':\'\'}\n    archive = {\'sha256\':\'6\'*64,\'bytes\':16384,\'unchanged\':True,\'config_image_id\':config_id,\n               \'target_digest\':None,\'platform_manifest_digest\':None,\'docker_id_kind\':\'CONFIG\',\'auth\':auth}\n    if profile != \'LEGACY_CONFIG\':\n        config_desc = desc(config,SR_CONFIG_MEDIA[0]); layer_desc = desc(layer,SR_LAYER_MEDIA[0])\n        config_proof.update(descriptor=config_desc,canonical=member(\'blobs/sha256/\'+config_id[7:],config))\n        layer_proof.update(descriptor=layer_desc,canonical=member(\'blobs/sha256/\'+layer_desc[\'digest\'][7:],layer),uncompressed_tar_proven=None)\n        manifest = sr_canonical({\'schemaVersion\':2,\'mediaType\':SR_MANIFEST_MEDIA[0],\n                                \'config\':wire(config_desc),\'layers\':[wire(layer_desc)]})\n        manifest_pair = pair(manifest,SR_MANIFEST_MEDIA[0])\n        if profile == \'OCI_INDEX\':\n            selected = {**wire(manifest_pair[\'descriptor\']),\'platform\':{\'os\':\'linux\',\'architecture\':\'amd64\'}}\n            target = pair(sr_canonical({\'schemaVersion\':2,\'mediaType\':SR_INDEX_MEDIA[0],\'manifests\':[selected]}),SR_INDEX_MEDIA[0])\n            auth[\'platform_manifest\'] = manifest_pair\n        else: target = manifest_pair\n        auth.update(target=target,wrapper=blob(\'index.json\',sr_canonical({\'schemaVersion\':2,\'manifests\':[wire(target[\'descriptor\'])]})))\n        image.update(id=target[\'descriptor\'][\'digest\'],inspect_descriptor=copy.deepcopy(target[\'descriptor\']))\n        archive.update(target_digest=image[\'id\'],platform_manifest_digest=manifest_pair[\'descriptor\'][\'digest\'],\n                       docker_id_kind=\'INDEX\' if profile == \'OCI_INDEX\' else \'MANIFEST\')\n    evidence[\'schemaVersion\'] = 2\n    evidence[\'image\'],evidence[\'archive\'] = image,archive\n    evidence[\'build\'].pop(\'metadata_config_image_id\',None)\n    evidence[\'build\'].update(iid_image_id=config_id,metadata_image_id=config_id,\n                            metadata_image_key=\'containerimage.config.digest\',metadata_image_role=\'CONFIG\')\n    evidence[\'witness\'][\'image_id\'] = image[\'id\']\n    report[\'Metadata\'][\'ImageID\'] = config_id\n    return evidence,report\n\n\ndef sr_data_controls():\n    """Run finite synthetic DATA through this same reducer; no SDK execution."""\n    passed = 0; count = 0\n    def b64(raw): return base64.b64encode(raw).decode(\'ascii\')\n    def member(path, raw):\n        return {\'path\':path,\'sha256\':sr_digest(raw),\'bytes\':len(raw),\'data_b64\':b64(raw)}\n    def fixture():\n        project = b\'\'\'[project]\nname = "synthetic-connector"\nversion = "1.0.0"\nrequires-python = ">=3.11,<3.12"\ndependencies = ["alpha>=1.0", "beta>=2.0"]\n[tool.uv]\npackage = false\n\'\'\'\n        lock = b\'\'\'version = 1\nrevision = 3\nrequires-python = "==3.11.*"\n[[package]]\nname = "alpha"\nversion = "1.2.0"\nsource = {registry = "https://pypi.org/simple"}\ndependencies = [{name = "beta"}]\n[[package]]\nname = "beta"\nversion = "2.0.0"\nsource = {registry = "https://pypi.org/simple"}\n[[package]]\nname = "synthetic-connector"\nversion = "1.0.0"\nsource = {virtual = "."}\ndependencies = [{name = "alpha"}, {name = "beta"}]\n[package.metadata]\nrequires-dist = [{name = "alpha", specifier = ">=1.0"}, {name = "beta", specifier = ">=2.0"}]\n\'\'\'\n        before = {path:{\'sha256\':sr_digest(b\'synthetic source\'), \'bytes\':16} for path in SR_REQUIRED_SOURCE}\n        before[SR_PROJECT] = {\'sha256\':sr_digest(project),\'bytes\':len(project)}\n        before[SR_LOCK] = {\'sha256\':sr_digest(lock),\'bytes\':len(lock)}\n        before[\'sycope/empty.py\'] = {\'sha256\':sr_digest(b\'\'),\'bytes\':0}\n        metadata = [member(SR_VENV+\'/lib/python3.11/site-packages/alpha-1.2.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: alpha\\nVersion: 1.2.0\\n\\nSynthetic only.\\n\'),\n                    member(SR_VENV+\'/lib/python3.11/site-packages/beta-2.0.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: beta\\nVersion: 2.0.0\\n\'),\n                    member(\'/usr/local/lib/python3.11/site-packages/global_tool-25.0.dist-info/METADATA\',b\'Metadata-Version: 2.3\\nName: global-tool\\nVersion: 25.0\\n\')]\n        release = b\'ID=debian\\nVERSION_ID="13"\\nNAME="Debian GNU/Linux"\\n\'\n        image = \'sha256:\'+\'1\'*64; scanner = \'sha256:\'+\'2\'*64\n        e = {\'schemaVersion\':1,\n             \'source\':{\'before\':before,\'after\':copy.deepcopy(before),\'context_sha256\':sr_digest(sr_canonical(before)),\'head\':\'a\'*40},\n             \'build\':{\'actual_exit\':0,\'metadata_config_image_id\':image,\'metadata_sha256\':\'5\'*64,\n                      \'uv\':{\'actual_build_material_join\':True,\'index_digest\':\'sha256:\'+\'3\'*64,\'index_sha256\':\'3\'*64,\n                            \'manifest_sha256\':\'4\'*64,\'material_digest\':\'sha256:\'+\'3\'*64,\n                            \'material_uri\':\'pkg:docker/ghcr.io/astral-sh/uv@0.12.8?platform=linux%2Famd64\',\n                            \'platform\':\'linux/amd64\',\'platform_manifest_digest\':\'sha256:\'+\'4\'*64,\'reference\':\'ghcr.io/astral-sh/uv:0.12.8\'}},\n             \'image\':{\'id\':image,\'iid_matches\':True,\'os\':\'linux\',\'architecture\':\'amd64\',\'variant\':\'\'},\n             \'archive\':{\'bytes\':16384,\'image_id\':image,\'sha256\':\'6\'*64,\'unchanged\':True},\n             \'scanner\':{\'config_sha256\':sr_digest(b\'{}\\n\'),\'db_download_scan_only\':True,\'empty_cache_before\':True,\n                        \'help_flags\':sorted(SR_HELP_FLAGS),\'help_sha256\':\'7\'*64,\'ignore_sha256\':sr_digest(b\'\'),\'image_id\':scanner,\n                        \'same_cache\':True,\'scan_exit\':0,\'scan_utc\':\'2026-10-29T12:00:00Z\',\'version_after_exit\':0,\n                        \'version_after_utc\':\'2026-10-29T12:01:00Z\',\'version_before_b64\':b64(b\'{"Version":"0.57.1"}\'),\'version_before_exit\':0},\n             \'witness\':{\'complete\':True,\'image_id\':image,\'member_count\':100,\'rootfs_bytes\':32768,\'rootfs_sha256\':\'8\'*64,\n                        \'os_release\':{\'path\':\'/usr/lib/os-release\',\'sha256\':sr_digest(release),\'data_b64\':b64(release)},\n                        \'python\':{\'implementation\':\'cpython\',\'metadata\':metadata,\n                                  \'platform\':{\'os_name\':\'posix\',\'sys_platform\':\'linux\',\'platform_system\':\'Linux\',\'platform_machine\':\'x86_64\',\'platform_python_implementation\':\'CPython\'},\n                                  \'venv\':SR_VENV,\'version\':\'3.11.16\',\'version_metadata_sha256\':\'9\'*64},\n                        \'uv\':{\'requested_path\':\'/bin/uv\',\'resolved_path\':\'/usr/bin/uv\',\'aliases\':[\'/bin/uv\',\'/usr/bin/uv\'],\n                              \'sha256\':\'a\'*64,\'bytes\':4000,\'mode\':0o755,\'executable\':True},\n                        \'uvx\':{\'requested_path\':\'/bin/uvx\',\'resolved_path\':\'/usr/bin/uvx\',\'aliases\':[\'/bin/uvx\',\'/usr/bin/uvx\'],\n                               \'sha256\':\'b\'*64,\'bytes\':3000,\'mode\':0o755,\'executable\':True},\n                        \'node\':{\'applicability\':\'ABSENT\',\'metadata\':[],\'runtime_paths\':[]}},\n             \'inputs\':{\'no_dev\':True,\'pyproject_b64\':b64(project),\'selected_extras\':[],\'uv_lock_b64\':b64(lock)},\n             \'final\':{\'archive_unchanged\':True,\'cancelled\':False,\'containers_removed\':True,\'image_unchanged\':True,\n                      \'owned_cli_drain\':True,\'owned_image_removed\':True,\'private_context_removed\':True,\'source_unchanged\':True,\'uncertain\':False},\n             \'error_codes\':[]}\n        r = {\'SchemaVersion\':2,\'Metadata\':{\'ImageID\':image,\'OS\':{\'Family\':\'debian\',\'Name\':\'13.1\'}},\n             \'Results\':[{\'Target\':\'synthetic Debian 13\',\'Class\':\'os-pkgs\',\'Type\':\'debian\',\'Packages\':[{\'Name\':\'libc6\',\'Version\':\'2.41-1\'}]},\n                        {\'Target\':\'Python\',\'Class\':\'lang-pkgs\',\'Type\':\'python-pkg\',\'Packages\':[{\'Name\':\'alpha\',\'Version\':\'1.2.0\'},{\'Name\':\'beta\',\'Version\':\'2.0.0\'},{\'Name\':\'global-tool\',\'Version\':\'25.0\'}]},\n                        {\'Target\':\'usr/bin/uv\',\'Class\':\'lang-pkgs\',\'Type\':\'rustbinary\',\'Packages\':[{\'Name\':\'uv\',\'Version\':\'0.12.8\'},{\'Name\':\'serde\',\'Version\':\'1.0.228\'}]},\n                        {\'Target\':\'/usr/bin/uvx\',\'Class\':\'lang-pkgs\',\'Type\':\'rustbinary\',\'Packages\':[{\'Name\':\'uvx\',\'Version\':\'0.12.8\'},{\'Name\':\'tokio\',\'Version\':\'1.47.0\'},{\'Name\':\'serde\',\'Version\':\'1.0.228\'}]}]}\n        v = {\'Version\':\'0.57.1\',\'VulnerabilityDB\':{\'Version\':2,\'UpdatedAt\':\'2026-10-29T00:00:00Z\',\n                                                \'DownloadedAt\':\'2026-10-29T12:00:30Z\',\'NextUpdate\':\'2026-10-30T00:00:00Z\'}}\n        sr_control_archive(e,r)\n        return e,r,v\n    def result(data, expect, report_override=None, version_override=None):\n        nonlocal count,passed\n        e,r,v = data\n        rr = sr_canonical(r) if report_override is None else report_override\n        vv = sr_canonical(v) if version_override is None else version_override\n        out = validate_scan_evidence(e,rr,vv); check = validate_safe_summary(sr_canonical(out))\n        count += 1\n        if not (check[\'valid\'] is True and check[\'report\'] == out and out[\'status\'] == expect):\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        passed += 1\n        return out\n    def set_at(obj,path,value):\n        node = obj\n        for key in path[:-1]: node = node[key]\n        node[path[-1]] = copy.deepcopy(value)\n    def repack_input(e,key,raw):\n        path = SR_LOCK if key == \'uv_lock_b64\' else SR_PROJECT\n        e[\'inputs\'][key] = b64(raw); e[\'source\'][\'before\'][path] = {\'sha256\':sr_digest(raw),\'bytes\':len(raw)}\n        e[\'source\'][\'after\'] = copy.deepcopy(e[\'source\'][\'before\']); e[\'source\'][\'context_sha256\'] = sr_digest(sr_canonical(e[\'source\'][\'before\']))\n    def add_node(e,r):\n        e[\'witness\'][\'node\'] = {\'applicability\':\'PRESENT\',\'runtime_paths\':[\'/usr/bin/node\'],\n            \'metadata\':[member(\'/usr/local/lib/node_modules/demo/package.json\',b\'{"name":"demo","version":"1.2.3"}\')]}\n        r[\'Results\'].append({\'Target\':\'usr/local/lib/node_modules/demo/package.json\',\'Class\':\'lang-pkgs\',\'Type\':\'node-pkg\',\'Packages\':[{\'Name\':\'demo\',\'Version\':\'1.2.3\'}]})\n    def add_finding(e,r):\n        e[\'scanner\'][\'scan_exit\'] = 1\n        r[\'Results\'][0][\'Vulnerabilities\'] = [{\'VulnerabilityID\':\'CVE-2026-12345\',\'PkgName\':\'libc6\',\'InstalledVersion\':\'2.41-1\',\n                                            \'FixedVersion\':\'\',\'Severity\':\'HIGH\',\'Status\':\'will_not_fix\'}]\n    # Every positive is a separate synthetic fixture, never a claim about an SDK.\n    result(fixture(),\'PASS\')\n    data = fixture(); data[1][\'Metadata\'][\'OS\'][\'EOSL\'] = False; result(data,\'PASS\')\n    data = fixture(); data[1][\'Results\'][1][\'Target\'] = \'actual-metadata-target-can-vary\'; result(data,\'PASS\')\n    data = fixture(); data[1][\'Results\'][2][\'Target\'] = \'/bin/uv\'; result(data,\'PASS\')\n    data = fixture(); data[0][\'build\'][\'uv\'].update(index_digest=None,index_sha256=None,material_digest=data[0][\'build\'][\'uv\'][\'platform_manifest_digest\']); result(data,\'PASS\')\n    data = fixture(); add_node(data[0],data[1]); result(data,\'PASS\')\n    data = fixture(); raw = base64.b64decode(data[0][\'inputs\'][\'uv_lock_b64\']).replace(b\'revision = 3\',b\'revision = 5\')\n    repack_input(data[0],\'uv_lock_b64\',raw); result(data,\'PASS\')\n    data = fixture(); row = data[0][\'witness\'][\'python\'][\'metadata\'][2]\n    raw = base64.b64decode(row[\'data_b64\']).replace(b\'Name: global-tool\',b\'Name: global_tool\')\n    row.update(data_b64=b64(raw),sha256=sr_digest(raw),bytes=len(raw)); result(data,\'PASS\')\n    data = fixture(); release = b\'ID=debian\\nVERSION_ID="12"\\n\'\n    data[0][\'witness\'][\'os_release\'].update(data_b64=b64(release),sha256=sr_digest(release))\n    data[1][\'Metadata\'][\'OS\'][\'Name\'] = \'12.2\'; result(data,\'PASS\')\n    data = fixture(); raw = base64.b64decode(data[0][\'inputs\'][\'uv_lock_b64\'])\n    raw = raw.replace(b\'name = "beta"\\nversion = "2.0.0"\\nsource = {registry = "https://pypi.org/simple"}\',\n                      b\'name = "beta"\\nversion = "2.0.0"\\nsource = {registry = "https://pypi.org/simple"}\\ndependencies = [{name = "gamma"}]\')\n    raw += b\'\\n[[package]]\\nname="gamma"\\nversion="0.3.0"\\nsource={registry="https://pypi.org/simple"}\\n\'\n    repack_input(data[0],\'uv_lock_b64\',raw)\n    data[0][\'witness\'][\'python\'][\'metadata\'].append(member(SR_VENV+\'/lib/python3.11/site-packages/gamma-0.3.0.dist-info/METADATA\',b\'Name: gamma\\nVersion: 0.3.0\\n\'))\n    data[1][\'Results\'][1][\'Packages\'].append({\'Name\':\'gamma\',\'Version\':\'0.3.0\'}); result(data,\'PASS\')\n    data = fixture(); add_finding(data[0],data[1]); found = result(data,\'FINDINGS\')\n    if found[\'findings\'][0][\'fixed\'] != \'\' or found[\'findings\'][0][\'status\'] != \'will_not_fix\':\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    data = fixture(); data[0][\'error_codes\'] = [\'BUILD\']; result(data,\'ERROR\')\n    empty = validate_scan_evidence({},None,None); count += 1\n    if not (empty[\'status\'] == \'ERROR\' and validate_safe_summary(sr_canonical(empty))[\'valid\'] is True):\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    passed += 1\n    mutations = [\n        (0,[\'schemaVersion\'],True),(0,[\'source\',\'after\',\'sycope/empty.py\',\'bytes\'],False),\n        (0,[\'source\',\'context_sha256\'],\'0\'*64),(0,[\'build\',\'actual_exit\'],1),\n        (0,[\'build\',\'uv\',\'actual_build_material_join\'],False),(0,[\'build\',\'uv\',\'material_digest\'],\'sha256:\'+\'f\'*64),\n        (0,[\'build\',\'uv\',\'platform\'],\'linux/arm64\'),(0,[\'build\',\'metadata_image_id\'],\'sha256:\'+\'f\'*64),\n        (0,[\'archive\',\'config_image_id\'],\'sha256:\'+\'f\'*64),(0,[\'archive\',\'unchanged\'],False),\n        (0,[\'scanner\',\'image_id\'],fixture()[0][\'image\'][\'id\']),(0,[\'scanner\',\'scan_exit\'],2),\n        (0,[\'scanner\',\'scan_exit\'],1),(0,[\'scanner\',\'scan_exit\'],True),\n        (0,[\'scanner\',\'config_sha256\'],\'0\'*64),(0,[\'scanner\',\'ignore_sha256\'],\'0\'*64),\n        (0,[\'scanner\',\'empty_cache_before\'],False),(0,[\'scanner\',\'same_cache\'],False),\n        (0,[\'scanner\',\'version_after_exit\'],1),(0,[\'scanner\',\'db_download_scan_only\'],False),\n        (0,[\'witness\',\'complete\'],False),(0,[\'witness\',\'image_id\'],\'sha256:\'+\'f\'*64),\n        (0,[\'witness\',\'python\',\'version\'],\'3.12.1\'),(0,[\'witness\',\'python\',\'platform\',\'platform_machine\'],\'arm64\'),\n        (0,[\'witness\',\'python\',\'metadata\'],[]),(0,[\'witness\',\'uv\',\'executable\'],False),\n        (0,[\'witness\',\'uvx\',\'aliases\'],[\'/different/uvx\']),(0,[\'witness\',\'uv\',\'mode\'],0o777),\n        (0,[\'witness\',\'node\',\'applicability\'],\'UNKNOWN\'),(0,[\'inputs\',\'no_dev\'],False),\n        (0,[\'inputs\',\'selected_extras\'],[\'unobserved\']),(0,[\'final\',\'containers_removed\'],False),\n        (0,[\'final\',\'owned_cli_drain\'],False),(0,[\'final\',\'owned_image_removed\'],False),\n        (0,[\'final\',\'private_context_removed\'],False),(0,[\'final\',\'uncertain\'],True),\n        (0,[\'final\',\'cancelled\'],True),(0,[\'final\',\'source_unchanged\'],False),\n        (1,[\'SchemaVersion\'],2.0),(1,[\'Metadata\',\'ImageID\'],\'sha256:\'+\'f\'*64),\n        (1,[\'Metadata\',\'OS\',\'EOSL\'],True),(1,[\'Metadata\',\'OS\',\'EOSL\'],0),\n        (1,[\'Metadata\',\'OS\',\'Family\'],\'unrecognized\'),(1,[\'Results\',0,\'Packages\'],[]),\n        (1,[\'Results\',1,\'Packages\'],[]),(1,[\'Results\',1,\'Packages\',0,\'Version\'],\'9.9.9\'),\n        (1,[\'Results\',2,\'Packages\'],[]),(1,[\'Results\',3,\'Packages\'],[]),\n        (1,[\'Results\',2,\'Target\'],\'unwitnessed/bin/uv\'),(1,[\'Results\',0,\'Packages\'],{}),\n        (2,[\'Version\'],\'0.57.2\'),(2,[\'VulnerabilityDB\',\'Version\'],\'2\'),\n        (2,[\'VulnerabilityDB\',\'Version\'],2.0),(2,[\'VulnerabilityDB\',\'Version\'],True),\n        (2,[\'VulnerabilityDB\',\'UpdatedAt\'],\'0001-01-01T00:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'DownloadedAt\'],\'2026-10-28T12:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'DownloadedAt\'],\'2026-10-30T12:00:00Z\'),\n        (2,[\'VulnerabilityDB\',\'NextUpdate\'],\'not-a-time\')]\n    for which,path,value in mutations:\n        result(fixture(),\'PASS\')\n        data = fixture(); before = sr_canonical(data); set_at(data[which],path,value)\n        if sr_canonical(data) == before: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        result(data,\'ERROR\')\n    # Extra invalid data is added to an otherwise passing complete report. A\n    # permissive parser would therefore wrongly PASS, rather than reject a\n    # different missing required field and conceal the intended counterexample.\n    valid_raw = sr_canonical(fixture()[1])\n    for raw in (valid_raw[:-1]+b\',"SchemaVersion":2}\',valid_raw[:-1]+b\',"extra":NaN}\',\n                valid_raw[:-1]+b\',"extra":1e9999}\',valid_raw[:-1]+b\',"extra":"\\\\u0000"}\',\n                valid_raw[:-1]+b\',"\\\\ud800":1}\',valid_raw[:-1]+b\',"extra":"\\\\udfff"}\',valid_raw+b\'\\x80\',\n                valid_raw[:-1]+b\',"extra":\'+b\'[\'*33+b\'0\'+b\']\'*33+b\'}\'):\n        result(fixture(),\'PASS\'); result(fixture(),\'ERROR\',report_override=raw)\n    prefix = valid_raw[:-1]+b\',"extra":"\'; suffix = b\'"}\'\n    oversize = prefix+b\'x\'*(SR_RAW_MAX+1-len(prefix)-len(suffix))+suffix\n    result(fixture(),\'PASS\'); result(fixture(),\'ERROR\',report_override=oversize)\n    del oversize\n    result(fixture(),\'PASS\'); data = fixture(); raw = sr_canonical(data[2])[:-1]+b\',"Version":"0.57.1"}\'\n    result(data,\'ERROR\',version_override=raw)\n    # Test-local metadata/TOML transport is rehashed to reach semantic guards.\n    for change in (\'unknown_source\',\'marker\',\'virtual_root\',\'requirements\',\'extra_lock_record\'):\n        result(fixture(),\'PASS\'); data = fixture(); e = data[0]\n        lock = base64.b64decode(e[\'inputs\'][\'uv_lock_b64\'])\n        if change == \'unknown_source\': lock = lock.replace(b\'{registry = "https://pypi.org/simple"}\',b\'{git = "https://invalid.example/repo"}\',1)\n        elif change == \'marker\': lock = lock.replace(b\'{name = "beta"}\',b\'{name = "beta", marker = "python_version < \\\'3.0\\\'"}\',1)\n        elif change == \'virtual_root\': lock = lock.replace(b\'name = "synthetic-connector"\',b\'name = "other-connector"\')\n        elif change == \'requirements\': lock = lock.replace(b\'specifier = ">=2.0"\',b\'specifier = ">=9.0"\')\n        else: lock += b\'\\n[[package]]\\nname="unselected"\\nversion="1.0.0"\\nsource={registry="https://pypi.org/simple"}\\n\'\n        repack_input(e,\'uv_lock_b64\',lock); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); row = data[0][\'witness\'][\'python\'][\'metadata\'][0]\n    raw = base64.b64decode(row[\'data_b64\'])+b\'Name: alpha\\n\'; raw = raw.replace(b\'\\n\\nSynthetic only.\\n\',b\'\\n\')\n    row.update(data_b64=b64(raw),sha256=sr_digest(raw),bytes=len(raw)); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'python\'][\'metadata\'].pop(); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_node(data[0],data[1]); data[1][\'Results\'].pop(); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'node\'][\'applicability\'] = \'PRESENT\'; data[0][\'witness\'][\'node\'][\'runtime_paths\'] = [\'/usr/bin/node\']; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[1][\'Results\'].append({\'Target\':\'node\',\'Class\':\'lang-pkgs\',\'Type\':\'node-pkg\',\'Packages\':[{\'Name\':\'unobserved\',\'Version\':\'1.0.0\'}]}); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); data[0][\'witness\'][\'uvx\'][\'aliases\'].append(\'/bin/uv\'); result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[0][\'scanner\'][\'scan_exit\'] = 0; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'Severity\'] = \'LOW\'; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'PkgName\'] = {\'private\':\'never artifact this\'}; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[1][\'Results\'][0][\'Vulnerabilities\'][0][\'InstalledVersion\'] = \'999.0\'; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); data[0][\'final\'][\'owned_cli_drain\'] = False; result(data,\'ERROR\')\n    result(fixture(),\'PASS\'); data = fixture(); add_finding(data[0],data[1]); row = data[1][\'Results\'][0][\'Vulnerabilities\'][0]\n    row[\'FixedVersion\'] = \'1\'*512; data[1][\'Results\'][0][\'Vulnerabilities\'] = [copy.deepcopy(row) for _ in range(2500)]\n    result(data,\'ERROR\')\n    # Safe summary policy is checked for both ordinary and failure projections.\n    good = result(fixture(),\'PASS\')\n    for path,value in (([\'schemaVersion\'],2.0),([\'category\'],\'/private/path\'),([\'identities\',\'unknown\'],\'secret\'),\n                       ([\'coverage\',\'python\',\'installed_pairs\'],True),([\'actual_exit\'],1),([\'cleanup\'],False),\n                       ([\'db\',\'next_update\'],\'2026-10-28T00:00:00Z\')):\n        changed = copy.deepcopy(good); set_at(changed,path,value); count += 1\n        if validate_safe_summary(sr_canonical(changed)) != {\'valid\':False,\'report\':None}:\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        passed += 1\n    bad_error = sr_empty_summary(); bad_error[\'findings\'] = [{\'id\':\'CVE-1\',\'pkg\':{\'raw\':\'never\'},\'installed\':\'1\',\'fixed\':\'\',\'severity\':\'HIGH\',\'status\':None}]\n    count += 1\n    if validate_safe_summary(sr_canonical(bad_error)) != {\'valid\':False,\'report\':None}:\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    passed += 1\n    # Exact selected v2 bounds: complete baselines, then isolated test-local mutations.\n    def refresh_source_bounds(data):\n        source = data[0][\'source\']\n        source[\'after\'] = copy.deepcopy(source[\'before\'])\n        source[\'context_sha256\'] = sr_digest(sr_canonical(source[\'before\']))\n    # A row at16MiB and a4096-entry map are permitted; one above each must reject.\n    data = fixture(); data[0][\'source\'][\'before\'][\'sycope/bounds.py\'] = {\'sha256\':\'f\'*64,\'bytes\':16777216}\n    refresh_source_bounds(data); result(data,\'PASS\')\n    result(fixture(),\'PASS\'); data = fixture()\n    data[0][\'source\'][\'before\'][\'sycope/bounds.py\'] = {\'sha256\':\'f\'*64,\'bytes\':16777217}\n    refresh_source_bounds(data); result(data,\'ERROR\')\n    data = fixture(); before = data[0][\'source\'][\'before\']\n    for index in range(4096 - len(before)):\n        before[\'sycope/map-\'+str(index)+\'.py\'] = {\'sha256\':\'f\'*64,\'bytes\':0}\n    refresh_source_bounds(data); result(data,\'PASS\')\n    result(fixture(),\'PASS\'); data = fixture(); before = data[0][\'source\'][\'before\']\n    for index in range(4097 - len(before)):\n        before[\'sycope/map-\'+str(index)+\'.py\'] = {\'sha256\':\'f\'*64,\'bytes\':0}\n    refresh_source_bounds(data); result(data,\'ERROR\')\n    # Projected flags are bounded observations, not all advertised Trivy options.\n    data = fixture(); flags = data[0][\'scanner\'][\'help_flags\']\n    flags += [\'--bound-\'+str(index) for index in range(127 - len(flags))]\n    flags.append(\'x\'*128); result(data,\'PASS\')\n    result(fixture(),\'PASS\'); data = fixture(); flags = data[0][\'scanner\'][\'help_flags\']\n    flags += [\'--bound-\'+str(index) for index in range(129 - len(flags))]\n    result(data,\'ERROR\')\n    for extra_flag in (\'x\'*129,\'--bad\\nflag\',\'--bad\'+chr(127),\'\'):\n        result(fixture(),\'PASS\'); data = fixture()\n        data[0][\'scanner\'][\'help_flags\'].append(extra_flag); result(data,\'ERROR\')\n    # Numeric equivalence cannot bypass the actual Python version text cap.\n    data = fixture(); version = data[0][\'witness\'][\'python\'][\'version\']\n    data[0][\'witness\'][\'python\'][\'version\'] = \'0\'*(512-len(version))+version; result(data,\'PASS\')\n    result(fixture(),\'PASS\'); data = fixture(); version = data[0][\'witness\'][\'python\'][\'version\']\n    data[0][\'witness\'][\'python\'][\'version\'] = \'0\'*(513-len(version))+version; result(data,\'ERROR\')\n    data = fixture(); uri = data[0][\'build\'][\'uv\'][\'material_uri\']\n    data[0][\'build\'][\'uv\'][\'material_uri\'] = uri+\'a\'*(4096-len(uri)); result(data,\'PASS\')\n    for suffix in (\'\\n\',chr(127)):\n        result(fixture(),\'PASS\'); data = fixture()\n        data[0][\'build\'][\'uv\'][\'material_uri\'] += suffix; result(data,\'ERROR\')\n    extra = sr_archive_data_controls(fixture)\n    count += extra; passed += extra\n    return {\'status\':\'C04_REDUCER_DATA_CONTROLS_PASSED\',\'case_count\':count,\'passed\':passed,\'failed\':0}\n\n\ndef sr_archive_data_controls(factory):\n    """Finite v2 role/auth regressions over synthetic owner observations only."""\n    count = 0\n    def fixture(profile=\'OCI_INDEX\'):\n        e,r,v = factory(); sr_control_archive(e,r,profile); return e,r,v\n    def check(data, valid=True, status=\'PASS\'):\n        nonlocal count\n        e,r,v = data\n        checked = validate_archive_auth(e[\'image\'],e[\'archive\'])\n        if type(checked) is not dict or set(checked) != {\'valid\',\'reason\',\'roles\'} or checked[\'valid\'] is not valid:\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        if valid:\n            if checked[\'reason\'] != \'OK\' or type(checked[\'roles\']) is not dict or set(checked[\'roles\']) != {\n                \'docker_image_id\',\'docker_id_kind\',\'archive_identity_profile\',\'config_image_id\',\'target_digest\',\'platform_manifest_digest\'}:\n                raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        elif checked != {\'valid\':False,\'reason\':\'ARCHIVE_REJECTED\',\'roles\':None}:\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        result = validate_scan_evidence(e,sr_canonical(r),sr_canonical(v))\n        accepted = validate_safe_summary(sr_canonical(result))\n        if result[\'status\'] != status or accepted != {\'valid\':True,\'report\':result}:\n            raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        count += 1\n        return result\n    def member_bytes(blob, raw):\n        blob.update(sha256=sr_digest(raw),bytes=len(raw),data_b64=base64.b64encode(raw).decode(\'ascii\'))\n    def decoded(blob): return json.loads(base64.b64decode(blob[\'data_b64\']))\n    def wire(desc): return {\'mediaType\':desc[\'media_type\'],\'digest\':desc[\'digest\'],\'size\':desc[\'bytes\']}\n    def pair_bytes(pair, raw):\n        pair[\'descriptor\'].update(digest=\'sha256:\'+sr_digest(raw),bytes=len(raw))\n        pair[\'blob\'][\'path\'] = \'blobs/sha256/\'+pair[\'descriptor\'][\'digest\'][7:]\n        member_bytes(pair[\'blob\'],raw)\n    def target_doc(data, doc):\n        e,r,_v = data; a = e[\'archive\']; auth = a[\'auth\']\n        pair_bytes(auth[\'target\'],sr_canonical(doc)); target = auth[\'target\'][\'descriptor\']\n        e[\'image\'].update(id=target[\'digest\'],inspect_descriptor=copy.deepcopy(target))\n        a[\'target_digest\'] = target[\'digest\']; e[\'witness\'][\'image_id\'] = target[\'digest\']\n        member_bytes(auth[\'wrapper\'],sr_canonical({\'schemaVersion\':2,\'manifests\':[wire(target)]}))\n        if auth[\'profile\'] == \'OCI_MANIFEST\': a[\'platform_manifest_digest\'] = target[\'digest\']\n        if e[\'build\'][\'metadata_image_role\'] == \'DOCKER\':\n            e[\'build\'].update(metadata_image_id=target[\'digest\'],iid_image_id=target[\'digest\'])\n    def manifest_doc(data, doc):\n        e,_r,_v = data; a = e[\'archive\']; auth = a[\'auth\']\n        if auth[\'profile\'] == \'OCI_MANIFEST\': target_doc(data,doc)\n        else:\n            previous = auth[\'platform_manifest\'][\'descriptor\'][\'digest\']\n            pair_bytes(auth[\'platform_manifest\'],sr_canonical(doc))\n            current = auth[\'platform_manifest\'][\'descriptor\']; root = decoded(auth[\'target\'][\'blob\'])\n            for row in root[\'manifests\']:\n                if row[\'digest\'] == previous: row.update(wire(current))\n            target_doc(data,root); a[\'platform_manifest_digest\'] = current[\'digest\']\n    def config_bytes(data, raw):\n        e,r,_v = data; a = e[\'archive\']; auth = a[\'auth\']; proof = auth[\'config\']\n        config_id = \'sha256:\'+sr_digest(raw)\n        proof[\'data_b64\'] = base64.b64encode(raw).decode(\'ascii\')\n        for row in (proof[\'canonical\'],proof[\'consumer\']): row.update(sha256=config_id[7:],bytes=len(raw))\n        a[\'config_image_id\'] = config_id; r[\'Metadata\'][\'ImageID\'] = config_id\n        if auth[\'profile\'] == \'LEGACY_CONFIG\':\n            e[\'image\'][\'id\'] = config_id; e[\'witness\'][\'image_id\'] = config_id\n        else:\n            proof[\'descriptor\'].update(digest=config_id,bytes=len(raw)); proof[\'canonical\'][\'path\'] = \'blobs/sha256/\'+config_id[7:]\n            selected = auth[\'platform_manifest\'] if auth[\'profile\'] == \'OCI_INDEX\' else auth[\'target\']\n            doc = decoded(selected[\'blob\']); doc[\'config\'] = wire(proof[\'descriptor\']); manifest_doc(data,doc)\n        if e[\'build\'][\'metadata_image_role\'] == \'CONFIG\':\n            e[\'build\'].update(metadata_image_id=config_id,iid_image_id=config_id)\n    for profile in (\'LEGACY_CONFIG\',\'OCI_MANIFEST\',\'OCI_INDEX\'): check(fixture(profile))\n    data = fixture(); data[0][\'scanner\'][\'scan_exit\'] = 1\n    data[1][\'Results\'][0][\'Vulnerabilities\'] = [{\'VulnerabilityID\':\'CVE-2026-12345\',\'PkgName\':\'libc6\',\n        \'InstalledVersion\':\'2.41-1\',\'FixedVersion\':\'\',\'Severity\':\'HIGH\',\'Status\':\'will_not_fix\'}]\n    check(data,True,\'FINDINGS\')\n    data = fixture(); e = data[0]; e[\'build\'].update(metadata_image_key=\'containerimage.digest\',metadata_image_role=\'DOCKER\',\n        metadata_image_id=e[\'image\'][\'id\'],iid_image_id=e[\'image\'][\'id\']); check(data)\n    data = fixture(\'LEGACY_CONFIG\'); e = data[0]; proof = e[\'archive\'][\'auth\'][\'config\']\n    desc = {\'media_type\':SR_CONFIG_MEDIA[1],\'digest\':e[\'archive\'][\'config_image_id\'],\'bytes\':proof[\'canonical\'][\'bytes\']}\n    proof.update(descriptor=desc); proof[\'canonical\'][\'path\'] = \'blobs/sha256/\'+desc[\'digest\'][7:]\n    e[\'image\'][\'inspect_descriptor\'] = copy.deepcopy(desc); check(data)\n    data = fixture(); raw = json.dumps(decoded(data[0][\'archive\'][\'auth\'][\'config\']),indent=2).encode()+b\'\\n\'\n    # decoded() expects a blob; configuration carries the same data_b64 key.\n    config_bytes(data,raw); check(data)\n    data = fixture(); cfg = decoded(data[0][\'archive\'][\'auth\'][\'config\']); cfg[\'config\'] = {\'Env\':[\'SYNTHETIC_PRIVATE_NEVER_PROJECT=example\']}\n    config_bytes(data,sr_canonical(cfg)); output = check(data)\n    if b\'SYNTHETIC_PRIVATE_NEVER_PROJECT\' in sr_canonical(output): raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    data = fixture(); root = decoded(data[0][\'archive\'][\'auth\'][\'target\'][\'blob\'])\n    root[\'manifests\'].append({\'mediaType\':\'opaque/unsupported\',\'digest\':\'sha512:unclaimed\',\n                              \'platform\':{\'os\':\'linux\',\'architecture\':\'arm64\'}})\n    target_doc(data,root); check(data)\n    # Direct paired paths may coincide only when they truly name the same member.\n    data = fixture(\'OCI_MANIFEST\'); auth = data[0][\'archive\'][\'auth\']; legacy = decoded(auth[\'legacy_manifest\'])\n    auth[\'config\'][\'consumer\'] = copy.deepcopy(auth[\'config\'][\'canonical\']); legacy[0][\'Config\'] = auth[\'config\'][\'consumer\'][\'path\']\n    auth[\'layers\'][0][\'consumer\'] = copy.deepcopy(auth[\'layers\'][0][\'canonical\']); legacy[0][\'Layers\'] = [auth[\'layers\'][0][\'consumer\'][\'path\']]\n    member_bytes(auth[\'legacy_manifest\'],sr_canonical(legacy)); check(data)\n    mutations = [\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'held_one_fd\'],False,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'complete_outer_tar\'],False,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'path_after\',\'inode\'],19,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'fd_after\',\'bytes\'],16385,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'sha256_after\'],\'0\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'fd_before\',\'mode\'],0o644,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'fd_before\',\'links\'],2,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'source_fd\',\'fd_before\',\'uid\'],True,False),\n        (\'OCI_INDEX\',[\'archive\',\'config_image_id\'],\'sha256:\'+\'f\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'target_digest\'],\'sha256:\'+\'f\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'platform_manifest_digest\'],\'sha256:\'+\'f\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'target\',\'blob\',\'path\'],\'consumer/target.lookalike\',False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'config\',\'canonical\',\'path\'],\'consumer/config.payload\',False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'config\',\'consumer\',\'sha256\'],\'0\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'config\',\'consumer\',\'bytes\'],True,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'layers\',0,\'canonical\',\'path\'],\'consumer/layer.payload\',False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'layers\',0,\'consumer\',\'bytes\'],17,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'layers\',0,\'consumer\',\'sha256\'],\'0\'*64,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'layers\',0,\'uncompressed_tar_proven\'],True,False),\n        (\'OCI_INDEX\',[\'image\',\'inspect_descriptor\'],None,False),\n        (\'OCI_INDEX\',[\'image\',\'inspect_descriptor\',\'bytes\'],True,False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'profile\'],\'UNKNOWN\',False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'wrapper\',\'path\'],\'wrapper/lookalike.json\',False),\n        (\'OCI_INDEX\',[\'archive\',\'auth\',\'legacy_manifest\',\'path\'],\'compat/lookalike.json\',False),\n        (\'LEGACY_CONFIG\',[\'archive\',\'auth\',\'layers\',0,\'uncompressed_tar_proven\'],False,False),\n        (\'LEGACY_CONFIG\',[\'archive\',\'auth\',\'layers\',0,\'uncompressed_tar_proven\'],None,False),\n        (\'LEGACY_CONFIG\',[\'archive\',\'docker_id_kind\'],\'INDEX\',False),\n        (\'OCI_INDEX\',[\'build\',\'iid_image_id\'],\'sha256:\'+\'f\'*64,True),\n        (\'OCI_INDEX\',[\'build\',\'metadata_image_role\'],\'DOCKER\',True),\n        (\'OCI_INDEX\',[\'build\',\'metadata_image_key\'],\'unknown.key\',True),\n        (\'OCI_INDEX\',[\'archive\',\'unchanged\'],False,True),\n        (\'OCI_INDEX\',[\'schemaVersion\'],1,True),\n    ]\n    for profile,path,value,valid in mutations:\n        check(fixture(profile)); data = fixture(profile); before = sr_canonical(data); node = data[0]\n        for key in path[:-1]: node = node[key]\n        node[path[-1]] = copy.deepcopy(value)\n        if sr_canonical(data) == before: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        check(data,valid,\'ERROR\')\n    check(fixture()); data = fixture(); data[1][\'Metadata\'][\'ImageID\'] = data[0][\'image\'][\'id\']; check(data,True,\'ERROR\')\n    # Test-local byte/hash/descriptor transport is refreshed to reach deep guards.\n    for change in (\'multiple_records\',\'config_alias\',\'layer_alias\',\'layer_sources\'):\n        check(fixture()); data = fixture(); blob = data[0][\'archive\'][\'auth\'][\'legacy_manifest\']; doc = decoded(blob)\n        if change == \'multiple_records\': doc.append(copy.deepcopy(doc[0]))\n        elif change == \'config_alias\': doc[0][\'Config\'] = \'./\'+doc[0][\'Config\']\n        elif change == \'layer_alias\': doc[0][\'Layers\'][0] = \'different/layer.payload\'\n        else: doc[0][\'LayerSources\'] = {\'unsupported\':{}}\n        member_bytes(blob,sr_canonical(doc)); check(data,False,\'ERROR\')\n    for change in (\'duplicate_platform\',\'wrong_platform\',\'nested_index\',\'selected_urls\'):\n        check(fixture()); data = fixture(); root = decoded(data[0][\'archive\'][\'auth\'][\'target\'][\'blob\'])\n        if change == \'duplicate_platform\': root[\'manifests\'].append(copy.deepcopy(root[\'manifests\'][0]))\n        elif change == \'wrong_platform\': root[\'manifests\'][0][\'platform\'][\'architecture\'] = \'arm64\'\n        elif change == \'nested_index\': root[\'manifests\'][0][\'mediaType\'] = SR_INDEX_MEDIA[0]\n        else: root[\'manifests\'][0][\'urls\'] = [\'https://invalid.example/never-fetch\']\n        target_doc(data,root); check(data,False,\'ERROR\')\n    for change in (\'config_os\',\'config_diffids\',\'unknown_layer\',\'foreign_layer\',\'layer_size\',\'layer_count\'):\n        check(fixture()); data = fixture(); auth = data[0][\'archive\'][\'auth\']\n        if change in (\'config_os\',\'config_diffids\'):\n            cfg = decoded(auth[\'config\'])\n            if change == \'config_os\': cfg[\'os\'] = \'windows\'\n            else: cfg[\'rootfs\'][\'diff_ids\'] = []\n            config_bytes(data,sr_canonical(cfg))\n        else:\n            doc = decoded(auth[\'platform_manifest\'][\'blob\'])\n            if change == \'unknown_layer\': doc[\'layers\'][0][\'mediaType\'] = \'application/vnd.oci.image.layer.v1.tar+zstd\'; auth[\'layers\'][0][\'descriptor\'][\'media_type\'] = doc[\'layers\'][0][\'mediaType\']\n            elif change == \'foreign_layer\': doc[\'layers\'][0][\'mediaType\'] = \'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip\'; auth[\'layers\'][0][\'descriptor\'][\'media_type\'] = doc[\'layers\'][0][\'mediaType\']\n            elif change == \'layer_size\': doc[\'layers\'][0][\'size\'] += 1\n            else: doc[\'layers\'] = []\n            manifest_doc(data,doc)\n        check(data,False,\'ERROR\')\n    check(fixture()); data = fixture(); auth = data[0][\'archive\'][\'auth\']\n    auth[\'config\'][\'consumer\'][\'path\'] = auth[\'layers\'][0][\'consumer\'][\'path\']\n    legacy = decoded(auth[\'legacy_manifest\']); legacy[0][\'Config\'] = auth[\'config\'][\'consumer\'][\'path\']\n    member_bytes(auth[\'legacy_manifest\'],sr_canonical(legacy)); check(data,False,\'ERROR\')\n    check(fixture()); data = fixture(); data[0][\'archive\'][\'bytes\'] = 5120\n    for name in (\'fd_before\',\'path_before\',\'fd_after\',\'path_after\'):\n        data[0][\'archive\'][\'auth\'][\'source_fd\'][name][\'bytes\'] = 5120\n    check(data,False,\'ERROR\')\n    check(fixture(\'LEGACY_CONFIG\')); data = fixture(\'LEGACY_CONFIG\'); cfg = decoded(data[0][\'archive\'][\'auth\'][\'config\'])\n    cfg[\'rootfs\'][\'diff_ids\'] = [\'sha256:\'+\'f\'*64]; config_bytes(data,sr_canonical(cfg)); check(data,False,\'ERROR\')\n    # Oversized complete metadata remains otherwise a valid observation; no drops.\n    check(fixture()); data = fixture(); raw = b\'Name: global-tool\\nVersion: 25.0\\n\\n\'+b\'x\'*900000\n    for index in range(14):\n        data[0][\'witness\'][\'python\'][\'metadata\'].append({\'path\':\'/usr/local/lib/python3.11/site-packages/global-copy-\'+str(index)+\'.dist-info/METADATA\',\n            \'sha256\':sr_digest(raw),\'bytes\':len(raw),\'data_b64\':base64.b64encode(raw).decode(\'ascii\')})\n    check(data,True,\'ERROR\')\n    # Canonical decoder tests isolate padding faults from unrelated hash guards.\n    for invalid in (\'AB==\',\'AAB=\',\'AAAA====\',\'AA==\\n\',\'AA--\',chr(233)):\n        if sr_b64(\'AA==\',1,\'ARCHIVE\') != b\'\\0\': raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        count += 1\n        try: sr_b64(invalid,SR_CONFIG_MAX,\'ARCHIVE\')\n        except SRRejected as error:\n            if error.code != \'ARCHIVE\': raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        else: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        count += 1\n    good = check(fixture())\n    for path,value in (([\'schemaVersion\'],1),([\'identities\',\'docker_image_id\'],good[\'identities\'][\'sdk_config_image_id\']),\n                       ([\'identities\',\'trivy_report_image_id\'],good[\'identities\'][\'docker_image_id\']),\n                       ([\'identities\',\'metadata_image_role\'],\'DOCKER\'),([\'identities\',\'sdk_target_digest\'],None)):\n        baseline = check(fixture()); modified = copy.deepcopy(baseline); node = modified\n        for key in path[:-1]: node = node[key]\n        node[path[-1]] = value\n        if sr_canonical(modified) == sr_canonical(good): raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        if validate_safe_summary(sr_canonical(modified)) != {\'valid\':False,\'report\':None}: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n        count += 1\n    check(fixture()); data = fixture(); cfg = data[0][\'archive\'][\'auth\'][\'config\']\n    raw = base64.b64decode(cfg[\'data_b64\'])[:-1]+b\',"os":"linux"}\'\n    config_bytes(data,raw); check(data,False,\'ERROR\')\n    # This bound is checked before base64 allocation, independently of hashes.\n    if sr_b64(base64.b64encode(b\'x\'*SR_CONFIG_MAX).decode(\'ascii\'),SR_CONFIG_MAX,\'ARCHIVE\') != b\'x\'*SR_CONFIG_MAX:\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    count += 1\n    if sr_b64(\'AA==\',1,\'ARCHIVE\') != b\'\\0\': raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    count += 1\n    try: sr_b64(\'AAA=\',1,\'ARCHIVE\')\n    except SRRejected as error:\n        if error.code != \'ARCHIVE\': raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    else: raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\')\n    count += 1\n    return count\n\n\ndef run_data_controls():\n    """Expose fixed failure text for all ordinary synthetic-control failures."""\n    try:\n        return sr_data_controls()\n    except Exception:\n        raise RuntimeError(\'C04_REDUCER_DATA_CONTROL_FAILED\') from None\n'
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
LINEAGE_FIELDS = ('config_present', 'config_matches', 'provenance_key_count', 'provenance_object', 'materials_list', 'materials_count', 'docker_material_count', 'selected_uv_count')
LINEAGE_BOOL_FIELDS = ('config_present', 'config_matches', 'provenance_object', 'materials_list')
LINEAGE_STAGES = ('UNOBSERVED', 'METADATA_READ', 'METADATA_JSON', 'METADATA_CONFIG', 'PROVENANCE_OBJECT', 'MATERIALS_LIST', 'MATERIAL_ROW', 'URI_PREFIX', 'URI_TAG', 'URI_QUERY', 'URI_QUALIFIER_KEYS', 'URI_PLATFORM', 'UV_IDENTITY', 'UV_SELECTION', 'MATERIAL_RAW_FETCH', 'MATERIAL_RAW_HASH', 'MATERIAL_RAW_JSON', 'MATERIAL_SCHEMA', 'INDEX_MANIFESTS', 'PLATFORM_DESCRIPTOR', 'CHILD_RAW_FETCH', 'CHILD_RAW_HASH', 'CHILD_RAW_JSON', 'FINAL_MANIFEST_SCHEMA', 'DONE', 'DIAGNOSTIC_UNAVAILABLE')
LINEAGE_STAGE = "UNOBSERVED"
LINEAGE_VALUES = dict.fromkeys(LINEAGE_FIELDS)
LINEAGE_BROKEN = False
LINEAGE_FALLBACK = '{"checkpoint":"DIAGNOSTIC_UNAVAILABLE","config_matches":null,"config_present":null,"docker_material_count":null,"materials_count":null,"materials_list":null,"provenance_key_count":null,"provenance_object":null,"scope":"C04_LINEAGE_DIAGNOSTIC_ONLY","selected_uv_count":null}\n'


class Failure(Exception):
    def __init__(self, code):
        self.code = code


def need(ok, code):
    if not ok:
        raise Failure(code)


def lineage_mark(checkpoint, **values):
    # Observation-only: diagnostic faults cannot replace an existing scan decision.
    global LINEAGE_STAGE, LINEAGE_BROKEN
    try:
        if type(checkpoint) is not str or checkpoint not in LINEAGE_STAGES or not set(values) <= set(LINEAGE_FIELDS):
            raise ValueError
        for name, value in values.items():
            if value is not None:
                if name in LINEAGE_BOOL_FIELDS:
                    if type(value) is not bool:
                        raise ValueError
                elif type(value) is not int or not 0 <= value <= 4194304:
                    raise ValueError
        LINEAGE_STAGE = checkpoint
        LINEAGE_VALUES.update(values)
    except Exception:
        LINEAGE_BROKEN = True


def lineage_diagnostic_line(checkpoint, observations, broken=False):
    # Only static field names, an enum and primitive values enter this console line.
    try:
        if type(broken) is not bool or broken or type(checkpoint) is not str or checkpoint not in LINEAGE_STAGES:
            raise ValueError
        if type(observations) is not dict or set(observations) != set(LINEAGE_FIELDS):
            raise ValueError
        projected = {'scope': 'C04_LINEAGE_DIAGNOSTIC_ONLY', 'checkpoint': checkpoint}
        for name in LINEAGE_FIELDS:
            value = observations[name]
            if value is not None:
                if name in LINEAGE_BOOL_FIELDS:
                    if type(value) is not bool:
                        raise ValueError
                elif type(value) is not int or not 0 <= value <= 4194304:
                    raise ValueError
            projected[name] = value
        line = json.dumps(projected, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n'
        if len(line.encode('ascii')) > 2048:
            raise ValueError
        return line
    except Exception:
        return LINEAGE_FALLBACK


def emit_lineage_diagnostic():
    # A failed diagnostic write never retries, changes the original error or skips cleanup.
    try:
        line = lineage_diagnostic_line(LINEAGE_STAGE, LINEAGE_VALUES, LINEAGE_BROKEN)
        sys.stderr.write(line)
        sys.stderr.flush()
    except Exception:
        pass


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
    environment = ['-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/tmp', 'TMPDIR=/cache',
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


ARCHIVE_CHECKPOINTS = ('UNOBSERVED', 'OPEN', 'HASH_BEFORE', 'PHYSICAL_TAR', 'MEMBERS',
    'LEGACY_RECORD', 'TARGET', 'PLATFORM', 'CONFIG', 'LAYERS', 'HASH_AFTER', 'PURE_AUTH')
ARCHIVE_CHECKPOINT = 'UNOBSERVED'
ARCHIVE_INDICES = ('application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json')
ARCHIVE_MANIFESTS = ('application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json')
ARCHIVE_CONFIGS = ('application/vnd.oci.image.config.v1+json',
    'application/vnd.docker.container.image.v1+json')


def archive_checkpoint(value):
    global ARCHIVE_CHECKPOINT
    if type(value) is str and value in ARCHIVE_CHECKPOINTS:
        ARCHIVE_CHECKPOINT = value


def emit_archive_checkpoint():
    try:
        checkpoint = ARCHIVE_CHECKPOINT if ARCHIVE_CHECKPOINT in ARCHIVE_CHECKPOINTS else 'UNOBSERVED'
        line = json.dumps({'scope': 'C04_ARCHIVE_CHECKPOINT_ONLY', 'checkpoint': checkpoint},
                          sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
        if len(line.encode('ascii')) <= 256:
            sys.stderr.write(line)
            sys.stderr.flush()
    except Exception:
        pass


def bounded_json_size(value, extra=0, code='OVERFLOW', cleanup=False):
    need(type(extra) is int and 0 <= extra <= 16 * 1048576, code)
    size = extra
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                               allow_nan=False, check_circular=True)
    for part in encoder.iterencode(value):
        size += len(part.encode('ascii'))
        need(size <= 16 * 1048576, code)
        work_check(cleanup)
    return size


def evidence_budget(prefix, slot, value, extra=0, code='OVERFLOW'):
    if prefix is None:
        return bounded_json_size(value, extra, code)
    candidate = dict(prefix)
    candidate[slot] = value
    return bounded_json_size(candidate, extra, code)


def stream_read_exact(stream, size, code):
    need(type(size) is int and 0 <= size <= 4 * 1048576, code)
    chunks = bytearray()
    while len(chunks) < size:
        work_check()
        part = stream.read(min(1048576, size - len(chunks)))
        need(type(part) is bytes and part, code)
        chunks.extend(part)
    return bytes(chunks)


def hash_held_stream(stream, size, code):
    need(type(size) is int and 0 < size <= MAX_ARCHIVE, code)
    stream.seek(0)
    sha = hashlib.sha256()
    count = 0
    while count < size:
        work_check()
        part = stream.read(min(1048576, size - count))
        need(type(part) is bytes and part, code)
        count += len(part)
        sha.update(part)
    need(stream.read(1) == b'', code)
    stream.seek(0)
    return sha.hexdigest()


def physical_tar_preflight(stream, size, code):
    """Bound physical extension reads before tarfile can allocate them; never extract."""
    need(type(size) is int and 0 < size <= MAX_ARCHIVE and size % 512 == 0, code)
    position = headers = metadata_bytes = 0
    global_size = local_size = None
    local_size_present = False
    extension_pending = False
    metadata_types = (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                      tarfile.GNUTYPE_LONGLINK)
    while True:
        work_check()
        need(position + 512 <= size, code)
        stream.seek(position)
        raw_header = stream_read_exact(stream, 512, code)
        if raw_header == b'\0' * 512:
            need(not extension_pending and position + 1024 <= size, code)
            need(stream_read_exact(stream, 512, code) == b'\0' * 512, code)
            remaining = size - position - 1024
            while remaining:
                part = stream_read_exact(stream, min(1048576, remaining), code)
                need(not part.strip(b'\0'), code)
                remaining -= len(part)
                work_check()
            need(stream.read(1) == b'', code)
            stream.seek(0)
            return {'headers': headers, 'metadata_bytes': metadata_bytes, 'end_offset': position}
        headers += 1
        need(headers <= 200000, code)
        try:
            header = tarfile.TarInfo.frombuf(raw_header, 'utf-8', 'strict')
        except (tarfile.HeaderError, ValueError, UnicodeError, OverflowError):
            raise Failure(code) from None
        need(type(header.size) is int and 0 <= header.size <= MAX_ARCHIVE and
             header.type != tarfile.GNUTYPE_SPARSE, code)
        physical_size = header.size
        if header.type in metadata_types:
            need(physical_size <= 1048576, code)
            metadata_bytes += physical_size
            need(metadata_bytes <= 16 * 1048576, code)
            need(position + 512 + ((physical_size + 511) // 512) * 512 <= size, code)
            data = stream_read_exact(stream, physical_size, code)
            extension_pending = True
            if header.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
                offset = 0
                size_override = None
                size_present = False
                while offset < len(data):
                    work_check()
                    space = data.find(b' ', offset, min(len(data), offset + 22))
                    need(space > offset and data[offset:space].isdigit(), code)
                    length = int(data[offset:space])
                    need(length > space - offset + 2 and offset + length <= len(data), code)
                    record = data[space + 1:offset + length]
                    need(record.endswith(b'\n') and b'=' in record[:-1], code)
                    key, value = record[:-1].split(b'=', 1)
                    need(key and not key.startswith(b'GNU.sparse'), code)
                    if key == b'size':
                        size_present = True
                        if value:
                            need(len(value) <= 20 and value.isdigit(), code)
                            size_override = int(value)
                            need(size_override <= MAX_ARCHIVE, code)
                    offset += length
                if size_present:
                    if header.type == tarfile.XGLTYPE:
                        global_size = size_override
                    else:
                        local_size = size_override
                        local_size_present = True
        else:
            if local_size_present:
                physical_size = header.size if local_size is None else local_size
            elif global_size is not None:
                physical_size = global_size
            local_size = None
            local_size_present = False
            extension_pending = False
        position += 512 + ((physical_size + 511) // 512) * 512
        need(position <= size, code)


def exact_tar_name(value):
    need(type(value) is str and 0 < len(value) <= 4096 and not value.startswith('/') and
         not value.endswith('/') and '\\' not in value and
         not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value) and
         all(part not in ('', '.', '..') for part in value.split('/')), 'ARCHIVE')
    return value


def archive_descriptor(value):
    need(type(value) is dict and not value.get('urls') and not value.get('data'), 'ARCHIVE')
    result = {'media_type': value.get('mediaType'), 'digest': value.get('digest'),
              'bytes': value.get('size')}
    need(type(result['media_type']) is str and type(result['digest']) is str and
         re.fullmatch('sha256:[0-9a-f]{64}', result['digest']) is not None and
         type(result['bytes']) is int and 0 < result['bytes'] <= MAX_ARCHIVE, 'ARCHIVE')
    return result


def archive_auth_roles(image, archive):
    checker = REDUCER.get('validate_archive_auth')
    need(callable(checker), 'INTERNAL')  # Historical PURE slot is intentionally inert until assembly.
    verdict = checker(image, archive)
    keys = {'docker_image_id', 'docker_id_kind', 'archive_identity_profile',
            'config_image_id', 'target_digest', 'platform_manifest_digest'}
    need(type(verdict) is dict and set(verdict) == {'valid', 'reason', 'roles'} and
         verdict['valid'] is True and verdict['reason'] == 'OK' and
         type(verdict['roles']) is dict and set(verdict['roles']) == keys, 'ARCHIVE')
    return verdict['roles']


def archive_fd_join(stream, path, before):
    current = info_identity(os.fstat(stream.fileno()))
    pathname = file_identity(path)
    need(current == before == pathname, 'ARCHIVE')
    return current, pathname


def archive_image(path, image, evidence_prefix=None):
    """Observe one owned save on a held FD; the shared PURE checker authorizes its roles."""
    archive_checkpoint('OPEN')
    path_before = file_identity(path)
    need(0 < path_before['bytes'] <= MAX_ARCHIVE, 'ARCHIVE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb', buffering=0) as stream:
        first = os.fstat(stream.fileno())
        need(stat.S_ISREG(first.st_mode) and info_identity(first) == path_before, 'ARCHIVE')
        archive_fd_join(stream, path, path_before)
        archive_checkpoint('HASH_BEFORE')
        archive_sha = hash_held_stream(stream, first.st_size, 'ARCHIVE')
        archive_checkpoint('PHYSICAL_TAR')
        physical = physical_tar_preflight(stream, first.st_size, 'ARCHIVE')
        result = {'sha256': archive_sha, 'bytes': first.st_size, 'unchanged': False,
                  'config_image_id': None, 'target_digest': None,
                  'platform_manifest_digest': None, 'docker_id_kind': None, 'auth': {
                    'profile': None, 'source_fd': None, 'wrapper': None, 'target': None,
                    'platform_manifest': None, 'config': None, 'layers': [], 'legacy_manifest': None}}
        auth = result['auth']
        def budget(extra=0):
            evidence_budget(evidence_prefix, 'archive', result, extra)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            archive_checkpoint('MEMBERS')
            members = {}
            for member in tar:
                work_check()
                need(len(members) < 200000 and member.name not in members and
                     (member.isfile() or member.isdir()) and member.sparse is None and
                     type(member.size) is int and 0 <= member.size <= MAX_ARCHIVE, 'ARCHIVE')
                if member.isdir():
                    name = member.name.rstrip('/')
                    if name not in ('', '.'):
                        exact_tar_name(name)
                else:
                    exact_tar_name(member.name)
                members[member.name] = member
            need(tar.offset == physical['end_offset'], 'ARCHIVE')
            cache = {}
            def read_member(name, cap=None, structural_tar=False):
                exact_tar_name(name)
                need(name in members and members[name].isfile(), 'ARCHIVE')
                member = members[name]
                need(0 < member.size <= MAX_ARCHIVE and
                     (cap is None or member.size <= cap), 'ARCHIVE')
                cached = cache.get(name)
                if cached is not None and (cap is None or cached[1] is not None) and not structural_tar:
                    return cached
                handle = tar.extractfile(member)
                need(handle is not None, 'ARCHIVE')
                sha = hashlib.sha256()
                raw = bytearray() if cap is not None else None
                count = 0
                with handle:
                    if structural_tar:
                        structure = physical_tar_preflight(handle, member.size, 'ARCHIVE')
                        with tarfile.open(fileobj=handle, mode='r:') as inner:
                            logical = 0
                            for _entry in inner:
                                work_check()
                                logical += 1
                                need(logical <= 200000, 'ARCHIVE')
                            need(inner.offset == structure['end_offset'], 'ARCHIVE')
                        handle.seek(0)
                    while count < member.size:
                        work_check()
                        part = handle.read(min(1048576, member.size - count))
                        need(type(part) is bytes and part, 'ARCHIVE')
                        count += len(part)
                        sha.update(part)
                        if raw is not None:
                            raw.extend(part)
                    need(handle.read(1) == b'', 'ARCHIVE')
                observed = {'path': name, 'sha256': sha.hexdigest(), 'bytes': count}
                data = bytes(raw) if raw is not None else None
                cache[name] = (observed, data)
                return observed, data
            def encode_blob(record, data):
                need(record.get('data_b64') == '', 'ARCHIVE')
                encoded_size = 4 * ((len(data) + 2) // 3)
                budget(encoded_size)
                record['data_b64'] = base64.b64encode(data).decode('ascii')
                budget()
            def json_blob(name):
                observed, data = read_member(name, 1048576)
                return {**observed, 'data_b64': ''}, data
            def canonical_name(descriptor):
                return 'blobs/sha256/' + descriptor['digest'][7:]
            archive_checkpoint('LEGACY_RECORD')
            legacy, legacy_raw = json_blob('manifest.json')
            auth['legacy_manifest'] = legacy
            encode_blob(legacy, legacy_raw)
            records = owner_json(legacy_raw, 1048576)
            need(type(records) is list and len(records) == 1 and type(records[0]) is dict, 'ARCHIVE')
            record = records[0]
            config_path = exact_tar_name(record.get('Config'))
            layer_paths = record.get('Layers')
            need(type(layer_paths) is list and 0 < len(layer_paths) <= 256, 'ARCHIVE')
            for name in layer_paths:
                exact_tar_name(name)
            descriptor = image['inspect_descriptor']
            manifest_record = None
            if descriptor is None or descriptor['media_type'] in ARCHIVE_CONFIGS:
                auth['profile'], result['docker_id_kind'] = 'LEGACY_CONFIG', 'CONFIG'
                config_descriptor = descriptor
                layer_descriptors = [None] * len(layer_paths)
            else:
                need(descriptor['media_type'] in ARCHIVE_INDICES + ARCHIVE_MANIFESTS, 'ARCHIVE')
                archive_checkpoint('TARGET')
                wrapper, wrapper_raw = json_blob('index.json')
                auth['wrapper'] = wrapper
                encode_blob(wrapper, wrapper_raw)
                target, target_raw = json_blob(canonical_name(descriptor))
                auth['target'] = {'descriptor': descriptor, 'blob': target}
                result['target_digest'] = descriptor['digest']
                encode_blob(target, target_raw)
                target_json = owner_json(target_raw, 1048576)
                if descriptor['media_type'] in ARCHIVE_INDICES:
                    auth['profile'], result['docker_id_kind'] = 'OCI_INDEX', 'INDEX'
                    archive_checkpoint('PLATFORM')
                    need(type(target_json) is dict and type(target_json.get('manifests')) is list and
                         len(target_json['manifests']) <= 200000, 'ARCHIVE')
                    matches = []
                    for item in target_json['manifests']:
                        work_check()
                        platform = item.get('platform') if type(item) is dict else None
                        if type(platform) is dict and platform.get('os') == 'linux' and \
                           platform.get('architecture') == 'amd64' and platform.get('variant', '') in ('', 'v1') and \
                           item.get('mediaType') in ARCHIVE_MANIFESTS:
                            matches.append(item)
                    need(len(matches) == 1, 'ARCHIVE')
                    selected = archive_descriptor(matches[0])
                    blob, raw = json_blob(canonical_name(selected))
                    auth['platform_manifest'] = {'descriptor': selected, 'blob': blob}
                    result['platform_manifest_digest'] = selected['digest']
                    encode_blob(blob, raw)
                    manifest_record = owner_json(raw, 1048576)
                else:
                    auth['profile'], result['docker_id_kind'] = 'OCI_MANIFEST', 'MANIFEST'
                    manifest_record = target_json
                    result['platform_manifest_digest'] = descriptor['digest']
                need(type(manifest_record) is dict and type(manifest_record.get('config')) is dict and
                     type(manifest_record.get('layers')) is list and
                     len(manifest_record['layers']) == len(layer_paths), 'ARCHIVE')
                config_descriptor = archive_descriptor(manifest_record['config'])
                layer_descriptors = [archive_descriptor(item) for item in manifest_record['layers']]
            archive_checkpoint('CONFIG')
            consumer_config, consumer_raw = read_member(config_path, 4194304)
            if config_descriptor is None:
                canonical_config, config_raw = consumer_config, consumer_raw
            else:
                canonical_config, config_raw = read_member(canonical_name(config_descriptor), 4194304)
            auth['config'] = {'descriptor': config_descriptor, 'canonical': canonical_config,
                              'consumer': consumer_config, 'data_b64': ''}
            result['config_image_id'] = 'sha256:' + consumer_config['sha256']
            encode_blob(auth['config'], config_raw)
            archive_checkpoint('LAYERS')
            for name, layer_descriptor in zip(layer_paths, layer_descriptors):
                work_check()
                legacy_profile = auth['profile'] == 'LEGACY_CONFIG'
                consumer, _data = read_member(name, structural_tar=legacy_profile)
                if layer_descriptor is None:
                    canonical_layer = consumer
                else:
                    canonical_layer, _data = read_member(canonical_name(layer_descriptor))
                auth['layers'].append({'descriptor': layer_descriptor, 'canonical': canonical_layer,
                    'consumer': consumer, 'uncompressed_tar_proven': True if legacy_profile else None})
                budget()
        archive_checkpoint('HASH_AFTER')
        after_hash = hash_held_stream(stream, first.st_size, 'ARCHIVE')
        fd_after, path_after = archive_fd_join(stream, path, path_before)
        need(info_identity(first) == fd_after == path_before == path_after and
             archive_sha == after_hash, 'ARCHIVE')
        auth['source_fd'] = {'fd_before': info_identity(first), 'path_before': path_before,
            'fd_after': fd_after, 'path_after': path_after, 'sha256_before': archive_sha,
            'sha256_after': after_hash, 'held_one_fd': True, 'complete_outer_tar': True}
        budget()
        archive_checkpoint('PURE_AUTH')
        roles = archive_auth_roles(image, result)
        return result, roles


def run_physical_tar_controls(write_fixture):
    """Direct same-preflight bounds: invalid cases otherwise have a complete valid tail."""
    import io
    count = 0
    def tar_piece(name, data, kind=tarfile.REGTYPE):
        info = tarfile.TarInfo(name)
        info.size, info.type, info.mode = len(data), kind, 0o600
        return info.tobuf(format=tarfile.USTAR_FORMAT) + data + b'\0' * ((-len(data)) % 512)
    ending = tar_piece('file', b'x') + b'\0' * 1024
    def observe(name, raw, reject=False):
        nonlocal count
        path = write_fixture(name, raw)
        with path.open('rb') as stream:
            try:
                physical_tar_preflight(stream, len(raw), 'WITNESS')
            except Failure as error:
                if not reject or type(error) is not Failure or error.code != 'WITNESS':
                    raise
            else:
                need(not reject, 'INTERNAL')
        count += 1
    def pax_payload(size):
        value = b'a' * size
        length = len(b' path=\n') + len(value) + 1
        while True:
            updated = len(str(length)) + len(b' path=\n') + len(value)
            if updated == length:
                return str(length).encode('ascii') + b' path=' + value + b'\n'
            length = updated
    observe('physical-basic.tar', ending)
    observe('physical-pax.tar', tar_piece('PaxHeader', pax_payload(256), tarfile.XHDTYPE) + ending)
    observe('physical-gnu.tar', tar_piece('././@LongLink', b'a' * 256 + b'\0', tarfile.GNUTYPE_LONGNAME) + ending)
    observe('physical-pax-limit.tar', tar_piece('PaxHeader', pax_payload(1048576), tarfile.XHDTYPE) + ending, True)
    observe('physical-gnu-limit.tar', tar_piece('././@LongLink', b'a' * 1048576 + b'\0', tarfile.GNUTYPE_LONGNAME) + ending, True)
    one = tar_piece('././@LongLink', b'a' * (1048576 - 1) + b'\0', tarfile.GNUTYPE_LONGNAME)
    observe('physical-total-limit.tar', one * 17 + ending, True)
    need(count == 6, 'INTERNAL')
    return {'status': 'PASS', 'case_count': count, 'passed': count, 'failed': 0}


def run_archive_controls(write_fixture):
    """Synthetic complete same-reader archives; no Docker/product/scan execution."""
    import io
    cases = 0
    def tar_bytes(entries):
        target = io.BytesIO()
        with tarfile.open(fileobj=target, mode='w:', format=tarfile.USTAR_FORMAT) as writer:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o600, len(data)
                writer.addfile(info, io.BytesIO(data))
            end = writer.offset
        return target.getvalue(), end
    layer, _end = tar_bytes([('data', b'synthetic layer')])
    def fixture(profile, fault=None):
        actual_layer = layer if fault != 'legacy-compressed' else b'\x1f\x8b' + b'x' * (len(layer) - 2)
        config_raw = canonical({'architecture': 'amd64', 'os': 'linux',
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + digest(actual_layer)]}, 'config': {}})
        config_id = 'sha256:' + digest(config_raw)
        cfg_desc = {'mediaType': ARCHIVE_CONFIGS[0], 'digest': config_id, 'size': len(config_raw)}
        layer_desc = {'mediaType': 'application/vnd.oci.image.layer.v1.tar',
                      'digest': 'sha256:' + digest(actual_layer), 'size': len(actual_layer)}
        manifest_raw = canonical({'schemaVersion': 2, 'mediaType': ARCHIVE_MANIFESTS[0],
                                  'config': cfg_desc, 'layers': [layer_desc]})
        manifest_desc = {'mediaType': ARCHIVE_MANIFESTS[0], 'digest': 'sha256:' + digest(manifest_raw),
                         'size': len(manifest_raw)}
        cfg_name, layer_name = 'consumer/config.data', 'consumer/layer.data'
        legacy_raw = canonical([{'Config': cfg_name, 'Layers': [layer_name]}])
        entries = [('manifest.json', legacy_raw), (cfg_name, config_raw), (layer_name, actual_layer)]
        image = {'id': config_id, 'inspect_descriptor': None, 'os': 'linux', 'architecture': 'amd64', 'variant': ''}
        if profile != 'LEGACY_CONFIG':
            target_desc, target_raw = manifest_desc, manifest_raw
            if profile == 'OCI_INDEX':
                selected = {**manifest_desc, 'platform': {'os': 'linux', 'architecture': 'amd64'}}
                target_raw = canonical({'schemaVersion': 2, 'mediaType': ARCHIVE_INDICES[0], 'manifests': [selected]})
                target_desc = {'mediaType': ARCHIVE_INDICES[0], 'digest': 'sha256:' + digest(target_raw), 'size': len(target_raw)}
                entries.append(('blobs/sha256/' + manifest_desc['digest'][7:], manifest_raw))
            wrapper = canonical({'schemaVersion': 2, 'mediaType': ARCHIVE_INDICES[0], 'manifests': [target_desc]})
            entries += [('index.json', wrapper), ('blobs/sha256/' + target_desc['digest'][7:], target_raw),
                        ('blobs/sha256/' + config_id[7:], config_raw),
                        ('blobs/sha256/' + layer_desc['digest'][7:], actual_layer)]
            image['id'], image['inspect_descriptor'] = target_desc['digest'], archive_descriptor(target_desc)
        if fault == 'missing-canonical':
            entries = [(name, data) for name, data in entries if name != 'blobs/sha256/' + config_id[7:]]
        elif fault == 'wrong-consumer':
            entries = [(name, b'{}' if name == cfg_name else data) for name, data in entries]
        elif fault == 'wrong-layer':
            entries = [(name, data + b'x' if name == layer_name else data) for name, data in entries]
        elif fault == 'wrong-target':
            entries = [(name, data + b' ' if name == 'blobs/sha256/' + image['id'][7:] else data) for name, data in entries]
        raw, end = tar_bytes(entries)
        if fault == 'trailer':
            raw += b'x' * 512
        elif fault == 'end-markers':
            raw = raw[:end]
        return raw, image, config_id
    def observe(name, profile, fault=None):
        nonlocal cases
        raw, image, config_id = fixture(profile, fault)
        path = write_fixture(name, raw)
        try:
            archive, roles = archive_image(path, image)
        except Failure as error:
            if fault is None or type(error) is not Failure or error.code != 'ARCHIVE':
                raise
        else:
            need(fault is None and roles['config_image_id'] == config_id and
                 roles['docker_image_id'] == image['id'] and archive['auth']['source_fd']['complete_outer_tar'] is True,
                 'INTERNAL')
            if profile != 'LEGACY_CONFIG':
                need(image['id'] != config_id and archive['auth']['config']['canonical']['path'] !=
                     archive['auth']['config']['consumer']['path'], 'INTERNAL')
        cases += 1
    observe('archive-manifest.tar', 'OCI_MANIFEST')
    observe('archive-index.tar', 'OCI_INDEX')
    observe('archive-legacy.tar', 'LEGACY_CONFIG')
    for fault in ('missing-canonical', 'wrong-consumer', 'wrong-layer', 'wrong-target', 'trailer', 'end-markers'):
        observe('archive-' + fault + '.tar', 'OCI_MANIFEST', fault)
    observe('archive-legacy-gzip.tar', 'LEGACY_CONFIG', 'legacy-compressed')
    # Direct same-FD identity helper used by the production reader, with an actual private path substitution.
    raw, image, _config = fixture('OCI_MANIFEST')
    path = write_fixture('archive-fd-source.tar', raw)
    before = file_identity(path)
    need(hash_file(path, MAX_ARCHIVE) == digest(raw), 'INTERNAL')
    moved = path.with_name('archive-fd-held.tar')
    need(not moved.exists() and not moved.is_symlink(), 'INTERNAL')
    with path.open('rb') as held:
        path.rename(moved)
        try:
            replacement = write_fixture('archive-fd-source.tar', raw)
            need(hash_file(replacement, MAX_ARCHIVE) == digest(raw) and
                 file_identity(replacement) != before, 'INTERNAL')
            try:
                archive_fd_join(held, path, before)
            except Failure as error:
                need(type(error) is Failure and error.code == 'ARCHIVE', 'INTERNAL')
            else:
                raise Failure('INTERNAL')
        finally:
            if path.exists():
                path.unlink()
            moved.rename(path)
    cases += 1
    need(cases == 11, 'INTERNAL')
    archive_checkpoint('PURE_AUTH')
    archive_checkpoint('UNOBSERVED')
    try:
        archive_descriptor({'mediaType': ARCHIVE_CONFIGS[0], 'digest': None, 'size': 1})
    except Failure as error:
        need(type(error) is Failure and error.code == 'ARCHIVE' and
             ARCHIVE_CHECKPOINT == 'UNOBSERVED', 'INTERNAL')
    else:
        raise Failure('INTERNAL')
    cases += 1
    need(cases == 12, 'INTERNAL')
    return {'status': 'PASS', 'case_count': cases, 'passed': cases, 'failed': 0}


def material_uri(uri):
    lineage_mark('URI_PREFIX')
    need(type(uri) is str and 0 < len(uri) <= 2048 and uri.startswith('pkg:docker/'), 'LINEAGE')
    encoded = uri[len('pkg:docker/'):]
    path, separator, query = encoded.partition('?')
    lineage_mark('URI_TAG')
    need('#' not in path and path.count('@') == 1, 'LINEAGE')
    name, version = path.rsplit('@', 1)
    name, version = urllib.parse.unquote(name), urllib.parse.unquote(version)
    lineage_mark('URI_QUERY')
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True) if separator else []
    lineage_mark('URI_QUALIFIER_KEYS')
    need(len(pairs) == len({key for key, _value in pairs}), 'LINEAGE')
    qualifiers = dict(pairs)
    platform = qualifiers.get('platform')
    lineage_mark('URI_PLATFORM')
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


def metadata_image_id(metadata, config_id, docker_id):
    need(type(metadata) is dict, 'LINEAGE')
    if 'containerimage.config.digest' in metadata:
        key, role, expected = 'containerimage.config.digest', 'CONFIG', config_id
    else:
        key, role, expected = 'containerimage.digest', 'DOCKER', docker_id
    selected = metadata.get(key)
    need(type(selected) is str and re.fullmatch('sha256:[0-9a-f]{64}', selected) is not None and
         selected == expected, 'LINEAGE')
    return {'metadata_image_id': selected, 'metadata_image_key': key, 'metadata_image_role': role}


def run_metadata_selector_controls():
    config_id, docker_id, other = ('sha256:' + letter * 64 for letter in ('a', 'b', 'c'))
    legacy = {'containerimage.config.digest': config_id, 'containerimage.digest': docker_id}
    generic = {'containerimage.digest': docker_id}
    count = 0
    for fixture, expected, role in ((dict(legacy), config_id, 'CONFIG'), (dict(generic), docker_id, 'DOCKER')):
        selected = metadata_image_id(fixture, config_id, docker_id)
        need(selected['metadata_image_id'] == expected and selected['metadata_image_role'] == role, 'INTERNAL')
        count += 1
    negatives = (
        {'containerimage.config.digest': None, 'containerimage.digest': docker_id},
        {'containerimage.config.digest': docker_id, 'containerimage.digest': docker_id},
        {}, {'containerimage.digest': other}, {'containerimage.digest': True},
    )
    for fixture in negatives:
        need(metadata_image_id(dict(legacy), config_id, docker_id)['metadata_image_id'] == config_id, 'INTERNAL')
        count += 1
        try:
            metadata_image_id(dict(fixture), config_id, docker_id)
        except Failure as error:
            need(type(error) is Failure and error.code == 'LINEAGE', 'INTERNAL')
        else:
            raise Failure('INTERNAL')
        count += 1
    return {'status': 'PASS', 'case_count': count, 'passed': count, 'failed': 0}


def build_lineage(metadata_raw):
    lineage_mark('METADATA_JSON')
    meta = owner_json(metadata_raw, 4194304)
    keys = [key for key in meta if key == 'buildx.build.provenance' or
            key == 'buildx.build.provenance/linux/amd64']
    lineage_mark('PROVENANCE_OBJECT', provenance_key_count=len(keys),
        provenance_object=(type(meta[keys[0]]) is dict) if len(keys) == 1 else None)
    need(len(keys) == 1 and type(meta[keys[0]]) is dict, 'LINEAGE')
    provenance = meta[keys[0]]
    lineage_mark('MATERIALS_LIST', materials_list=type(provenance.get('materials')) is list,
        materials_count=len(provenance['materials']) if type(provenance.get('materials')) is list else None,
        docker_material_count=sum(1 for row in provenance['materials'] if type(row) is dict and
            type(row.get('uri')) is str and row['uri'].startswith('pkg:docker/'))
            if type(provenance.get('materials')) is list else None)
    need(type(provenance.get('materials')) is list and provenance['materials'], 'LINEAGE')
    selected = []
    for row in provenance['materials']:
        lineage_mark('MATERIAL_ROW')
        need(type(row) is dict and type(row.get('uri')) is str and type(row.get('digest')) is dict, 'LINEAGE')
        if row['uri'].startswith('pkg:docker/'):
            try:
                name, version, platform = material_uri(row['uri'])
            except Failure:
                if 'astral-sh' in row['uri'] or '/uv@' in row['uri']:
                    raise
                continue
            if name == 'ghcr.io/astral-sh/uv':
                lineage_mark('UV_IDENTITY')
                need(version == '0.12.8' and platform == 'linux/amd64' and
                     set(row['digest']) == {'sha256'} and
                     re.fullmatch('[0-9a-f]{64}', row['digest']['sha256']) is not None, 'LINEAGE')
                selected.append(row)
    lineage_mark('UV_SELECTION', selected_uv_count=len(selected))
    need(len(selected) == 1, 'LINEAGE')
    material = selected[0]
    material_digest = 'sha256:' + material['digest']['sha256']
    reference = 'ghcr.io/astral-sh/uv@' + material_digest
    lineage_mark('MATERIAL_RAW_FETCH')
    raw = cli(['docker', 'buildx', 'imagetools', 'inspect', '--raw', reference], 120, stdout_cap=2097152)
    lineage_mark('MATERIAL_RAW_HASH')
    raw = exact_manifest_bytes(raw, material_digest)
    lineage_mark('MATERIAL_RAW_JSON')
    record = owner_json(raw)
    lineage_mark('MATERIAL_SCHEMA')
    need(type(record) is dict and type(record.get('schemaVersion')) is int and record['schemaVersion'] == 2 and type(record.get('mediaType')) is str,
         'LINEAGE')
    index_digest = index_sha = None
    if record['mediaType'] in ('application/vnd.oci.image.index.v1+json',
                               'application/vnd.docker.distribution.manifest.list.v2+json'):
        lineage_mark('INDEX_MANIFESTS')
        need(type(record.get('manifests')) is list, 'LINEAGE')
        matching = [row for row in record['manifests'] if type(row) is dict and type(row.get('platform')) is dict and
                    row['platform'].get('os') == 'linux' and row['platform'].get('architecture') == 'amd64' and
                    row['platform'].get('variant', '') in ('', 'v1')]
        lineage_mark('PLATFORM_DESCRIPTOR')
        need(len(matching) == 1 and type(matching[0].get('digest')) is str and
             re.fullmatch('sha256:[0-9a-f]{64}', matching[0]['digest']) is not None and
             matching[0]['mediaType'] in ('application/vnd.oci.image.manifest.v1+json',
                                        'application/vnd.docker.distribution.manifest.v2+json'), 'LINEAGE')
        index_digest, index_sha = material_digest, digest(raw)
        chosen = matching[0]['digest']
        lineage_mark('CHILD_RAW_FETCH')
        raw = cli(['docker', 'buildx', 'imagetools', 'inspect', '--raw',
                   'ghcr.io/astral-sh/uv@' + chosen], 120, stdout_cap=2097152)
        lineage_mark('CHILD_RAW_HASH')
        raw = exact_manifest_bytes(raw, chosen)
        lineage_mark('CHILD_RAW_JSON')
        record = owner_json(raw)
    else:
        chosen = material_digest
    lineage_mark('FINAL_MANIFEST_SCHEMA')
    need(type(record.get('schemaVersion')) is int and record['schemaVersion'] == 2 and record.get('mediaType') in ('application/vnd.oci.image.manifest.v1+json',
                                    'application/vnd.docker.distribution.manifest.v2+json') and
         type(record.get('config')) is dict and type(record.get('layers')) is list and record['layers'] and
         re.fullmatch('sha256:[0-9a-f]{64}', record['config'].get('digest', '')) is not None, 'LINEAGE')
    lineage_mark('DONE')
    return {'reference': 'ghcr.io/astral-sh/uv:0.12.8', 'material_uri': material['uri'],
            'material_digest': material_digest, 'index_digest': index_digest,
            'platform_manifest_digest': chosen, 'platform': 'linux/amd64',
            'index_sha256': index_sha, 'manifest_sha256': digest(raw), 'actual_build_material_join': True}


def inspect_rootfs(path, image_id, image_info, evidence_prefix=None):
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
    metadata_budget_rows = []

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
        physical = physical_tar_preflight(stream, before['bytes'], 'WITNESS')
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
            need(archive.offset == physical['end_offset'] and
                 0 <= archive.offset <= before['bytes'] - 1024, 'WITNESS')
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
                row = {'path': '/' + clean(name), 'sha256': digest(raw), 'bytes': len(raw), 'data_b64': ''}
                metadata_budget_rows.append(row)
                evidence_budget(evidence_prefix, 'witness', {'metadata': metadata_budget_rows},
                                4 * ((len(raw) + 2) // 3), code='WITNESS')
                row['data_b64'] = base64.b64encode(raw).decode('ascii')
                evidence_budget(evidence_prefix, 'witness', {'metadata': metadata_budget_rows}, code='WITNESS')
                return row

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
            os_release = {key: os_release[key] for key in ('path', 'sha256', 'data_b64')}
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
    evidence_budget(evidence_prefix, 'witness', result, code='WITNESS')
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

    def tar_bytes(rows, fmt=tarfile.PAX_FORMAT):
        sink = io.BytesIO()
        with tarfile.open(fileobj=sink, mode='w', format=fmt) as output:
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
    long_name = 'opt/' + 'long-segment-' * 16 + '/extra-1.0.dist-info/METADATA'
    for fmt, label in ((tarfile.PAX_FORMAT, 'pax'), (tarfile.GNU_FORMAT, 'gnu')):
        rows = entries + [(long_name, 'file', package),
                          ('extra-long-link.dist-info/METADATA', 'hardlink', long_name)]
        raw, _end = tar_bytes(rows, fmt)
        seen = inspect_rootfs(write_fixture('valid-' + label + '-long.tar', raw), image_id, image_info)
        names = {row['path'] for row in seen['python']['metadata']}
        need('/' + long_name in names and '/extra-long-link.dist-info/METADATA' in names, 'WITNESS')
        cases += 1
    need(cases == 14, 'WITNESS')
    os_observed = inspect_rootfs(write_fixture('os-release-seam.tar', complete), image_id, image_info)
    need(REDUCER['sr_os_release'](os_observed['os_release']) == '13', 'WITNESS')
    cases += 1
    need(cases == 15, 'WITNESS')
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


def scanner_diagnostic(code, stdout, stderr):
    names = ('unknown_flag','db_download','db_schema','network','tls','rate_limit','permission','no_space','archive_load','unsupported')
    result = {'scope':'C04_SCANNER_DIAGNOSTIC_ONLY','checkpoint':'SCAN_RETURN',
              'exit':None,'stdout_bytes':None,'stderr_bytes':None,**{name:False for name in names}}
    if not (type(code) is int and 0 <= code <= 255 and type(stdout) is bytes and
            len(stdout) <= 67108864 and type(stderr) is bytes and len(stderr) <= 2097152):
        return result
    result.update(exit=code,stdout_bytes=len(stdout),stderr_bytes=len(stderr))
    lower = stderr.lower()
    signatures = ((b'unknown flag',),(b'failed to download',b'failed to fetch vulnerability db'),
        (b'database schema',b'unsupported db version',b'db schema'),
        (b'network is unreachable',b'no such host',b'connection refused',b'i/o timeout',b'dial tcp'),
        (b'tls handshake',b'x509:',b'certificate signed by unknown authority'),
        (b'too many requests',b'toomanyrequests',b'429'),(b'permission denied',),
        (b'no space left on device',),(b'failed to load image',b'failed to open archive',b'unable to initialize an image'),
        (b'unsupported media type',b'unsupported image',b'unsupported platform',b'unsupported flag'))
    for name, patterns in zip(names, signatures): result[name] = any(value in lower for value in patterns)
    return result


def emit_scanner_diagnostic(code, stdout, stderr):
    fallback = b'{"archive_load":false,"checkpoint":"SCAN_RETURN","db_download":false,"db_schema":false,"exit":null,"network":false,"no_space":false,"permission":false,"rate_limit":false,"scope":"C04_SCANNER_DIAGNOSTIC_ONLY","stderr_bytes":null,"stdout_bytes":null,"tls":false,"unknown_flag":false,"unsupported":false}\n'
    try:
        line = canonical(scanner_diagnostic(code,stdout,stderr))+b'\n'
        if len(line) > 1024: line = fallback
    except Exception:
        line = fallback
    try:
        sys.stderr.write(line.decode('ascii'))
        sys.stderr.flush()
    except Exception:
        pass


def run_scanner_diagnostic_controls():
    fixtures = (
        (1,b'{}',b'failed to download vulnerability DB; database schema; dial tcp; x509:; too many requests',
         {'db_download','db_schema','network','tls','rate_limit'}),
        (2,b'',b'unknown flag; permission denied; no space left on device; failed to load image; unsupported platform',
         {'unknown_flag','permission','no_space','archive_load','unsupported'}),
        (255,b'PRIVATE_SCANNER_CANARY /private/example',b'PRIVATE_SCANNER_CANARY https://example.invalid/token',set()),
        (1,b'{}',b'x'*2097153,set()))
    count = 0
    for code, stdout, stderr, expected in fixtures:
        result = scanner_diagnostic(code,stdout,stderr)
        need(set(result) == {'scope','checkpoint','exit','stdout_bytes','stderr_bytes',
             'unknown_flag','db_download','db_schema','network','tls','rate_limit','permission','no_space','archive_load','unsupported'},'INTERNAL')
        flags = {name for name in expected | {'unknown_flag','db_download','db_schema','network','tls','rate_limit','permission','no_space','archive_load','unsupported'} if result[name] is True}
        need(flags == expected and all(type(result[name]) is bool for name in flags | {'unknown_flag','db_download','db_schema','network','tls','rate_limit','permission','no_space','archive_load','unsupported'}),'INTERNAL')
        need(result['scope'] == 'C04_SCANNER_DIAGNOSTIC_ONLY' and result['checkpoint'] == 'SCAN_RETURN' and
             result['exit'] == (None if len(stderr)>2097152 else code) and
             result['stdout_bytes'] == (None if len(stderr)>2097152 else len(stdout)) and
             result['stderr_bytes'] == (None if len(stderr)>2097152 else len(stderr)) and
             len(canonical(result))+1 <= 1024 and b'PRIVATE_SCANNER_CANARY' not in canonical(result),'INTERNAL')
        count += 1
    return {'status':'PASS','case_count':count,'passed':count,'failed':0}


def os_diagnostic(evidence, report_raw):
    fields = ('metadata_ok','name_ok','witness_release_ok','major_match','table_known','supported_at_scan',
              'eosl_ok','extended_ok','os_result_count','os_package_rows','os_pair_count','os_pairs_ok','os_inventory_nonempty')
    result = {'scope':'C04_OS_PREDICATES_ONLY','checkpoint':'UNOBSERVED',**{key:None for key in fields}}
    unavailable = {**result,'checkpoint':'DIAGNOSTIC_UNAVAILABLE'}
    try:
        check = REDUCER['sr_need']
        report = REDUCER['sr_json'](report_raw,REDUCER['SR_RAW_MAX'])
        if type(report) is not dict or type(report.get('Metadata')) is not dict: return unavailable
        osmeta = report['Metadata'].get('OS')
        result['checkpoint'] = 'OS_METADATA'
        result['metadata_ok'] = type(osmeta) is dict and osmeta.get('Family') == 'debian'
        check(result['metadata_ok'],'OS')
        result.update(checkpoint='OS_NAME',name_ok=False)
        name = REDUCER['sr_text'](osmeta.get('Name'),32,'OS')
        result['name_ok'] = re.fullmatch(r'[0-9]+(?:\.[0-9]+)*',name) is not None
        check(result['name_ok'],'OS')
        result.update(checkpoint='WITNESS_RELEASE',witness_release_ok=False)
        major = REDUCER['sr_os_release'](evidence['witness']['os_release'])
        result['witness_release_ok'] = True
        result.update(checkpoint='MAJOR_JOIN',major_match=major == name.split('.')[0])
        check(result['major_match'],'OS')
        result.update(checkpoint='TAGGED_SUPPORT',table_known=major in REDUCER['SR_DEBIAN_EOL'])
        check(result['table_known'],'OS')
        result['supported_at_scan'] = REDUCER['sr_timestamp'](evidence['scanner']['scan_utc'],'OS') < REDUCER['sr_timestamp'](REDUCER['SR_DEBIAN_EOL'][major],'OS')
        check(result['supported_at_scan'],'OS')
        result.update(checkpoint='EOSL',eosl_ok='EOSL' not in osmeta or type(osmeta['EOSL']) is bool and osmeta['EOSL'] is False)
        check(result['eosl_ok'],'OS')
        result.update(checkpoint='EXTENDED',extended_ok='extended' not in osmeta or osmeta['extended'] is False)
        check(result['extended_ok'],'OS')
        rows = report.get('Results')
        if type(rows) is not list or not rows or not all(type(row) is dict for row in rows): return unavailable
        selected = [row for row in rows if row.get('Class') == 'os-pkgs']
        if len(selected) > 200000: return unavailable
        result.update(checkpoint='OS_PACKAGE_PAIRS',os_result_count=len(selected),os_package_rows=0,os_pair_count=0,os_pairs_ok=True)
        inventory = set()
        for row in selected:
            work_check(cleanup=True)
            result['os_pairs_ok'] = False
            packages = row.get('Packages',[])
            if type(packages) is list:
                result['os_package_rows'] += len(packages)
                if result['os_package_rows'] > 200000: return unavailable
            else: result['os_package_rows'] = None
            pairs = REDUCER['sr_pairs'](packages,'OS',row.get('Type') == 'python-pkg')
            check(row.get('Type') == 'debian' and pairs,'OS')
            inventory.update(pairs)
            if len(inventory) > 200000: return unavailable
            result.update(os_pair_count=len(inventory),os_pairs_ok=True)
        result.update(checkpoint='OS_INVENTORY',os_inventory_nonempty=bool(inventory))
        check(result['os_inventory_nonempty'],'OS')
        result['checkpoint'] = 'OS_GUARDS_OK'
        return result
    except Exception as error:
        if type(error) is REDUCER.get('SRRejected') and error.code == 'OS': return result
        return unavailable


def emit_os_diagnostic(evidence, report_raw):
    fallback = b'{"checkpoint":"DIAGNOSTIC_UNAVAILABLE","eosl_ok":null,"extended_ok":null,"major_match":null,"metadata_ok":null,"name_ok":null,"os_inventory_nonempty":null,"os_package_rows":null,"os_pair_count":null,"os_pairs_ok":null,"os_result_count":null,"scope":"C04_OS_PREDICATES_ONLY","supported_at_scan":null,"table_known":null,"witness_release_ok":null}\n'
    try:
        line = canonical(os_diagnostic(evidence,report_raw))+b'\n'
        if len(line) > 1024: line = fallback
    except Exception:
        line = fallback
    try:
        sys.stderr.write(line.decode('ascii'))
        sys.stderr.flush()
    except Exception:
        pass


def run_os_diagnostic_controls():
    count = 0
    for change, expected in (('positive-private','OS_GUARDS_OK'),('absent-os','OS_METADATA'),
                             ('unsupported','TAGGED_SUPPORT'),('packages','OS_PACKAGE_PAIRS')):
        release = b'ID=debian\nVERSION_ID="13"\n'
        report = {'Metadata':{'OS':{'Family':'debian','Name':'13'}},'Results':[
            {'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'PRIVATE_OS_CANARY','Version':'1.0'}]}]}
        if change == 'absent-os': report['Metadata'].pop('OS')
        elif change == 'unsupported':
            release = b'ID=debian\nVERSION_ID="99"\n'; report['Metadata']['OS']['Name'] = '99'
        elif change == 'packages': report['Results'][0]['Packages'] = {}
        evidence = {'scanner':{'scan_utc':'2026-10-29T12:00:00Z'},'witness':{'os_release':{
            'path':'/etc/os-release','sha256':digest(release),
            'data_b64':base64.b64encode(release).decode('ascii')}}}
        result = os_diagnostic(evidence,canonical(report))
        names = {'metadata_ok','name_ok','witness_release_ok','major_match','table_known','supported_at_scan',
                 'eosl_ok','extended_ok','os_result_count','os_package_rows','os_pair_count','os_pairs_ok','os_inventory_nonempty'}
        need(set(result) == names | {'scope','checkpoint'} and result['scope'] == 'C04_OS_PREDICATES_ONLY' and
             result['checkpoint'] == expected and len(canonical(result))+1 <= 1024 and
             b'PRIVATE_OS_CANARY' not in canonical(result),'INTERNAL')
        for key in names:
            value = result[key]
            need(value is None or type(value) is int and 0 <= value <= 200000 if key in
                 {'os_result_count','os_package_rows','os_pair_count'} else value is None or type(value) is bool,'INTERNAL')
        count += 1
    return {'status':'PASS','case_count':count,'passed':count,'failed':0}


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
    need(callable(REDUCER.get('validate_archive_auth')), 'INTERNAL')  # New PURE must be assembled by Root.
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
        selector_controls = run_metadata_selector_controls()
        diagnostic_controls = run_scanner_diagnostic_controls()
        os_diagnostic_controls = run_os_diagnostic_controls()
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
                 type(data) is bytes and 0 < len(data) <= 32 * 1048576, 'INTERNAL')
            target = fixture_dir / name
            write_new(target, data)
            return target
        physical_controls = run_physical_tar_controls(write_fixture)
        archive_controls = run_archive_controls(write_fixture)
        witness_controls = run_witness_controls(write_fixture)
        need(type(witness_controls) is dict and set(witness_controls) == {'status','case_count','passed','failed'} and
             witness_controls['status'] == 'PASS' and type(witness_controls.get('case_count')) is int and
             type(witness_controls.get('passed')) is int and type(witness_controls.get('failed')) is int and
             0 < witness_controls['case_count'] == witness_controls['passed'] <= 4096 and witness_controls['failed'] == 0,
             'INTERNAL')
        print(json.dumps({'scope':'C04_SAME_CODE_CONTROLS_ONLY',
            'groups':{name:{key:value[key] for key in ('case_count','passed','failed')}
                      for name,value in (('reducer',controls),('capture',host_controls),('witness',witness_controls),
                      ('metadata_selector',selector_controls),('physical_tar',physical_controls),
                      ('archive_auth',archive_controls),('scanner_diagnostic',diagnostic_controls),
                      ('os_diagnostic',os_diagnostic_controls))}},
            sort_keys=True), flush=True)
        archive_checkpoint('UNOBSERVED')
        PHASE = 'TOOL'
        cli(['docker', 'version', '--format', '{{json .}}'])
        cli(['docker', 'buildx', 'version'])
        driver = cli(['docker', 'buildx', 'inspect', '--bootstrap'], 120)
        need(re.search(rb'^Driver:\s+docker\s*$', driver, re.M) is not None, 'TOOL')
        PHASE = 'SOURCE'
        context = root / 'context'
        head, before = source_context(checkout, context)
        evidence = {'schemaVersion': 2, 'source': {'head': head, 'before': before, 'after': None,
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
        need(re.fullmatch('sha256:[0-9a-f]{64}', iid) is not None and
             image['Config']['Labels'].get('org.trueid.c04.image') == nonce, 'BUILD')
        observed_descriptor = image.get('Descriptor')
        evidence['image'] = {'id': image['Id'], 'os': image['Os'], 'architecture': image['Architecture'],
            'variant': image.get('Variant', ''), 'inspect_descriptor':
            archive_descriptor(observed_descriptor) if observed_descriptor is not None else None}
        PHASE = 'ARCHIVE'
        archive = root / 'input/sdk.tar'
        cli(['docker', 'image', 'save', '--output', str(archive), image['Id']], 300)
        archive_row, archive_roles = archive_image(archive, evidence['image'], evidence)
        evidence['archive'] = archive_row
        PHASE = 'LINEAGE'
        lineage_mark('METADATA_READ')
        metadata_raw = read_file(root / 'build-metadata.json', 4194304)
        metadata = owner_json(metadata_raw, 4194304)
        lineage_mark('METADATA_CONFIG',
            config_present=('containerimage.config.digest' in metadata) if type(metadata) is dict else None,
            config_matches=(metadata.get('containerimage.config.digest') == archive_roles['config_image_id'])
                if type(metadata) is dict else None)
        selected_metadata = metadata_image_id(metadata, archive_roles['config_image_id'], archive_roles['docker_image_id'])
        need(iid == selected_metadata['metadata_image_id'], 'BUILD')
        evidence['build'] = {'actual_exit': code, 'metadata_sha256': digest(metadata_raw),
            'iid_image_id': iid, **selected_metadata, 'uv': build_lineage(metadata_raw)}
        bounded_json_size(evidence)
        PHASE = 'WITNESS'
        witness_intent, witness_cid = create_container(image['Id'], [], [], witness=True)
        try:
            rootfs = root / 'rootfs.tar'
            cli(['docker', 'export', '--output', str(rootfs), witness_cid], 300)
            witness_row = inspect_container(witness_cid)
            need(witness_row['State']['Status'] == 'created' and witness_row['State']['Running'] is False and
                 witness_row['State']['Pid'] == 0 and witness_row['Image'] == image['Id'], 'WITNESS')
            evidence['witness'] = inspect_rootfs(rootfs, image['Id'], image, evidence)
            bounded_json_size(evidence)
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
        need(file_identity(archive) == archive_row['auth']['source_fd']['path_after'] and
             hash_file(archive, MAX_ARCHIVE) == archive_row['sha256'], 'ARCHIVE')
        bounded_json_size(evidence)
        code, report_raw, scan_stderr, _elapsed = scanner(tool, prefix + ['--timeout', '10m', 'image',
            '--input', '/input/sdk.tar', '--scanners', 'vuln', '--pkg-types', 'os,library', '--list-all-pkgs',
            '--format', 'json', '--severity', 'HIGH,CRITICAL', '--exit-code', '1', '--ignorefile', '/control/empty.ignore'],
            mounts, seconds=600, network='bridge', scan=True)
        emit_scanner_diagnostic(code, report_raw, scan_stderr)
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
        need(file_identity(archive) == archive_row['auth']['source_fd']['path_after'] and
             hash_file(archive, MAX_ARCHIVE) == archive_row['sha256'], 'ARCHIVE')
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
        if code == 'LINEAGE':
            emit_lineage_diagnostic()
        if code == 'ARCHIVE':
            emit_archive_checkpoint()
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
        bounded_json_size(evidence, cleanup=True)
        result = REDUCER['validate_scan_evidence'](evidence, report_raw, version_raw)
        if CANCELLED or UNCERTAIN:
            need(result['status'] != 'PASS', 'INTERNAL')
        if result['status'] == 'ERROR' and result['category'] == 'OS':
            emit_os_diagnostic(evidence, report_raw)
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

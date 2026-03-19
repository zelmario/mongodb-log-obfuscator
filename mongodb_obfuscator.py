#!/usr/bin/env python3
"""
MongoDB Obfuscator — Logs & FTDC

Obfuscates sensitive data in MongoDB log files and FTDC (Full Time Diagnostic
Data Capture) files with coherent, consistent replacements across an entire
cluster.

Point it at a folder containing logs and diagnostic.data directories (at any
nesting depth) and it recreates the same directory structure with every
sensitive string replaced by a deterministic placeholder.  A single shared
registry guarantees that the same hostname, IP, database name, etc. receives
the same replacement in every file — logs and FTDC alike.

Output
------
  <output-dir>/          mirrors input structure
      node1/
          mongod_obfuscated.log
          diagnostic.data/
              metrics.2024-01-01T00-00-00Z-00000_obfuscated
      node2/
          ...
      cluster_mapping.json   (shared, one per run — keep private)

Dependencies: None (Python 3.6+ stdlib only)

Usage
-----
    python mongodb_obfuscator.py /path/to/cluster_dump/ -o /path/to/output/
    python mongodb_obfuscator.py node1.log node2.log metrics.ftdc -o output/
"""

import argparse
import json
import os
import re
import struct
import sys
import zlib
from collections import OrderedDict


# =============================================================================
# Configuration: attribute keys grouped by what they contain
# =============================================================================

HOST_KEYS = {
    # Direct host/port identifiers
    "host", "hostAndPort", "hostName",
    # Replication sync sources and candidates
    "syncSource", "syncSourceHost", "syncSourceCandidate",
    "candidateNode", "candidate", "peer",
    "newSyncSource", "oldSyncSource", "previousSyncSource",
    "currentSyncSource", "unsupportedSyncSource", "syncTarget",
    "eligibleCandidateSyncSource",
    # Remote/sender hosts
    "remoteHost", "senderHost", "donorHost",
    # Network endpoints and addresses
    "addr", "address", "addressString",
    "server", "serverAddress", "serverHost",
    "endpoint", "localEndpoint",
    # Cluster topology
    "primary", "newPrimary", "targetPrimary",
    "closestNode", "selectedNode", "node",
    "otherMember",
    # Request/cursor targets
    "requestTarget", "request_target", "request_target_host",
    "target", "cursorHost",
    # Failed hosts
    "failedHost",
    # SNI
    "sniName",
    # FTDC: serverStatus repl section
    "me",
}

REMOTE_LOCAL_KEYS = {
    "remote", "local", "remoteAddr", "remoteSocketAddress", "remoteString",
    "remoteAddress", "sourceClient",
}

CLIENT_KEYS = {"client"}

NAMESPACE_KEYS = {
    "ns", "namespace", "nss",
    # Namespace variants used in sharding, rename, resharding operations
    "sourceNss", "targetNss", "newNss", "oldNss",
    "sourceNamespace", "targetNamespace", "destinationNamespace",
    "originalCollection",
    "outputNamespace", "resolvedNs",
    "fromNs", "toNs",
    "oplogNamespace", "oplogNss",
    "ecocNss", "ecocCompactNss", "ecocRenameNss",
    "reshardingTmpNss", "lostAndFoundNss",
    "existingTargetNamespace", "newTargetNamespace",
    "configSettingsNamespace",
    "affectedNamespaces",
    "dbNss", "docNss",
}
DATABASE_KEYS = {"database", "db", "dbName", "dbname"}
COLLECTION_KEYS = {
    "collection", "coll", "collName",
    "tempCollection", "temporaryCollection", "newCollection",
    "sourceCollection", "defragmentCollection",
}
REPLSET_KEYS = {
    "replSetName", "setName", "configServerSetName",
    "replicaSet",
    # These contain replica set names in various contexts
    "newConfigSetName", "oldConfigSetName", "localConfigSetName",
    "commandLineSetName", "ourSetName", "initiateSetName",
    "remoteNodeSetName",
    # FTDC: replSetGetStatus top-level field
    "set",
}
USER_KEYS = {"user", "userName", "queryUser"}

PATH_KEYS = {
    "dbPath", "dbpath", "path", "filePath", "filepath",
    "localFilePath", "remoteFilePath",
    "keyfile", "cafile", "crlFile", "CRLFile",
    "configPath", "logPath", "newLogPath", "oldLogPath",
    # File paths from various operations
    "file", "fileName", "filename",
    "dir", "directory", "dataDirectory",
    "destFile", "srcFile", "localFile", "remoteFile",
    "lockFile", "jsonConfigPath",
    "remoteDBPath",
    "_pipeAbsolutePath",
}

CERT_SUBJECT_KEYS = {
    "peerSubject", "peerSubjectName", "subjectName", "subject", "issuer",
    "dn",
}

CONN_STRING_KEYS = {
    "targetClusterConnectionString", "connString", "connectionString",
    "replicaSetConnectionStr",
    "shardConnectionString",
    "newConnString", "oldConnString", "currentConnString",
    "newConnectionString", "givenConnString",
    "uri", "mongoUri", "ldapurl",
}

# Shard names/IDs reveal cluster topology and naming conventions
SHARD_KEYS = {
    "shard", "shardId",
    "fromShard", "fromShardId", "toShard", "toShardId",
    "donorShard", "donorShardId",
    "recipientShard", "recipientShardId", "recipientId",
    "coordinatorShardId", "writeShardId",
    "dataShard", "mergingShardId",
    "firstShardId", "secondShardId",
}

APP_NAME_KEYS = {"appName", "clientName"}

FREETEXT_KEYS = {"msg", "error", "errmsg", "reason", "message", "info",
                 "errorMessage", "errorMsg", "err_msg", "description", "desc"}

# Keys whose values are host lists (comma-separated or BSON arrays)
HOST_LIST_KEYS = {"addresses", "failedHosts", "nodes", "configServers",
                  "listenAddrs", "attemptedHosts",
                  # FTDC: replication arrays
                  "hosts", "passives", "arbiters", "advisoryHostFQDNs"}

# Keys to never touch (structural log fields, numeric metrics, safe metadata)
SKIP_KEYS = {
    # Log envelope fields
    "t", "s", "c", "id", "ctx", "svc", "tags",
    # Connection/session metrics (numeric)
    "connectionId", "connectionCount", "durationMillis", "millis",
    "workingMillis", "timeAcquiringMicros", "numYields", "nreturned",
    "docsExamined", "keysExamined", "nscanned", "cpuNanos",
    "durationMicros", "latency",
    # Transaction identifiers (numeric/opaque)
    "txnNumber", "clientTxnNumber", "opId",
    # Version strings (not sensitive)
    "version", "gitVersion", "openSSLVersion",
    "minWireVersion", "maxWireVersion",
    # Numeric settings and status codes
    "port", "votes", "priority", "term",
    "ok", "code", "codeName", "result",
    "featureCompatibilityVersion",
    # Numeric counters that appear frequently
    "numMembers", "numShards", "numChunks", "numDocs",
    "bytesCloned", "docsCloned", "keysInserted",
    "numRecords", "numIndexes",
}

# =============================================================================
# Embedded BSON: keys whose string values are SAFE and should NOT be obfuscated
# =============================================================================

# These are structural BSON/oplog keys — their values are operational, not PII
BSON_STRUCTURAL_KEYS = {
    # Oplog structure
    "op", "v", "t", "ts", "wall", "stmtId", "txnNumber", "prevOpTime",
    "ui", "lsid", "uid", "_id",
    # BSON type wrappers
    "$oid", "$uuid", "$date", "$timestamp", "$binary", "$numberLong",
    "$numberInt", "$numberDouble", "$numberDecimal", "$regularExpression",
    "$code", "$symbol", "$undefined", "$minKey", "$maxKey", "$dbPointer",
    # MongoDB command keys
    "find", "aggregate", "insert", "update", "delete", "findAndModify",
    "count", "distinct", "getMore", "explain", "verbosity",
    "shardVersion", "readConcern", "writeConcern", "provenance",
    "level", "batchSize", "maxTimeMS", "limit", "sort", "projection",
    "filter", "pipeline",
    # Diff/update operators
    "$v", "diff", "u", "i", "d", "$set", "$unset", "$inc", "$push",
    "$pull", "$addToSet", "$rename", "$min", "$max", "$mul",
    "$setOnInsert", "$currentDate", "$bit",
    # Index/collection meta
    "key", "unique", "sparse", "background", "expireAfterSeconds",
    "weights", "default_language", "language_override",
}

# Safe string values that appear in BSON documents and should never be obfuscated
BSON_SAFE_VALUES = {
    # Booleans
    "true", "false", "yes", "no", "Y", "N",
    # BSON/oplog operation types
    "u", "i", "d", "c", "n", "noop",
    # Common status values
    "ACTIVE", "INACTIVE", "DELETED", "PENDING", "COMPLETED", "FAILED",
    "APPROVED", "REJECTED", "CANCELLED", "EXPIRED",
    # Read/write concern levels
    "local", "majority", "linearizable", "available", "snapshot",
    "implicitDefault",
    # Common short tokens
    "null", "none", "undefined", "NaN",
}

# Two-letter country codes (ISO 3166-1 alpha-2) — not sensitive
COUNTRY_CODES = {
    "AF", "AL", "DZ", "AS", "AD", "AO", "AG", "AR", "AM", "AU", "AT",
    "AZ", "BS", "BH", "BD", "BB", "BY", "BE", "BZ", "BJ", "BT", "BO",
    "BA", "BW", "BR", "BN", "BG", "BF", "BI", "KH", "CM", "CA", "CV",
    "CF", "TD", "CL", "CN", "CO", "KM", "CG", "CD", "CR", "CI", "HR",
    "CU", "CY", "CZ", "DK", "DJ", "DM", "DO", "EC", "EG", "SV", "GQ",
    "ER", "EE", "ET", "FJ", "FI", "FR", "GA", "GM", "GE", "DE", "GH",
    "GR", "GD", "GT", "GN", "GW", "GY", "HT", "HN", "HU", "IS", "IN",
    "ID", "IR", "IQ", "IE", "IL", "IT", "JM", "JP", "JO", "KZ", "KE",
    "KI", "KP", "KR", "KW", "KG", "LA", "LV", "LB", "LS", "LR", "LY",
    "LI", "LT", "LU", "MK", "MG", "MW", "MY", "MV", "ML", "MT", "MH",
    "MR", "MU", "MX", "FM", "MD", "MC", "MN", "ME", "MA", "MZ", "MM",
    "NA", "NR", "NP", "NL", "NZ", "NI", "NE", "NG", "NO", "OM", "PK",
    "PW", "PA", "PG", "PY", "PE", "PH", "PL", "PT", "QA", "RO", "RU",
    "RW", "KN", "LC", "VC", "WS", "SM", "ST", "SA", "SN", "RS", "SC",
    "SL", "SG", "SK", "SI", "SB", "SO", "ZA", "SS", "ES", "LK", "SD",
    "SR", "SZ", "SE", "CH", "SY", "TW", "TJ", "TZ", "TH", "TL", "TG",
    "TO", "TT", "TN", "TR", "TM", "TV", "UG", "UA", "AE", "GB", "US",
    "UY", "UZ", "VU", "VE", "VN", "YE", "ZM", "ZW",
}

# Currency codes (ISO 4217) — not sensitive
CURRENCY_CODES = {
    "USD", "EUR", "GBP", "JPY", "CNY", "INR", "CAD", "AUD", "CHF", "HKD",
    "SGD", "SEK", "KRW", "NOK", "NZD", "MXN", "TWD", "ZAR", "BRL", "DKK",
    "PLN", "THB", "ILS", "IDR", "CZK", "AED", "TRY", "HUF", "CLP", "SAR",
    "PHP", "MYR", "COP", "RUB", "RON", "PEN", "BHD", "BGN", "ARS",
}


# =============================================================================
# Regex patterns
# =============================================================================

RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_FQDN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b'
)
RE_EMAIL = re.compile(r'\b[\w.+-]+@[\w.-]+\.\w{2,}\b')
RE_LDAP_DN_COMPONENT = re.compile(
    r'\b(?:DC|OU|CN|O|L|ST)=([A-Za-z][A-Za-z0-9 ._-]*)', re.IGNORECASE
)
RE_JAVA_CLASS = re.compile(r'\b((?:[a-z][a-z0-9]*\.){2,}[A-Z]\w*)\b')

# Extracts key: "value" pairs from stringified BSON
RE_BSON_STRING_FIELD = re.compile(r'(\w+):\s*"([^"]*)"')

# Values that are clearly not PII (numbers, hex, UUIDs, dates, booleans)
RE_PURE_NUMBER = re.compile(r'^-?\d+\.?\d*$')
RE_HEX = re.compile(r'^[0-9a-fA-F]{24,}$')
RE_UUID_LIKE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

KNOWN_NON_DOMAINS = {
    "system.version", "system.sessions", "system.profile",
    "system.views", "system.js", "system.users", "system.roles",
    "$cmd", "startup_log",
    "config.system.sessions", "config.system.version",
    "config.system.views", "config.system.js",
    "admin.system.version", "admin.system.users", "admin.system.roles",
    "local.system.replset", "local.system.js",
}

INTERNAL_DBS = {"admin", "local", "config"}


# =============================================================================
# BSON Type Wrappers — preserve type fidelity across decode → modify → encode
# =============================================================================

class Int32:
    __slots__ = ('value',)
    def __init__(self, v): self.value = v

class Int64:
    __slots__ = ('value',)
    def __init__(self, v): self.value = v

class BSONDatetime:
    __slots__ = ('value',)
    def __init__(self, v): self.value = v

class BSONTimestamp:
    __slots__ = ('inc', 'time')
    def __init__(self, inc, time): self.inc = inc; self.time = time

class BSONObjectId:
    __slots__ = ('data',)
    def __init__(self, data): self.data = data

class BSONBinary:
    __slots__ = ('subtype', 'data')
    def __init__(self, subtype, data): self.subtype = subtype; self.data = data

class BSONDecimal128:
    __slots__ = ('data',)
    def __init__(self, data): self.data = data

class BSONRegex:
    __slots__ = ('pattern', 'options')
    def __init__(self, pattern, options): self.pattern = pattern; self.options = options

class BSONCode:
    __slots__ = ('code',)
    def __init__(self, code): self.code = code

class BSONMinKey: pass
class BSONMaxKey: pass


# =============================================================================
# BSON Decoder
# =============================================================================

def _decode_cstring(data, pos):
    end = data.index(b'\x00', pos)
    return data[pos:end].decode('utf-8', errors='replace'), end + 1


def _decode_bson_string(data, pos):
    str_len = struct.unpack_from('<i', data, pos)[0]
    s = data[pos + 4:pos + 4 + str_len - 1].decode('utf-8', errors='replace')
    return s, pos + 4 + str_len


def decode_bson_doc(data, pos=0):
    """Decode a BSON document starting at *pos*.

    Returns (OrderedDict, position_after_document).
    Field order is preserved — critical for FTDC metric alignment.
    """
    if pos + 4 > len(data):
        raise ValueError(f"Not enough data for BSON length at pos {pos}")
    doc_len = struct.unpack_from('<i', data, pos)[0]
    if doc_len < 5:
        raise ValueError(f"Invalid BSON document length {doc_len} at pos {pos}")
    end_pos = pos + doc_len
    if end_pos > len(data):
        raise ValueError(
            f"BSON document length {doc_len} exceeds available data "
            f"({len(data) - pos} bytes) at pos {pos}")
    pos += 4
    doc = OrderedDict()

    while pos < end_pos - 1:
        type_byte = data[pos]
        pos += 1
        key, pos = _decode_cstring(data, pos)

        if type_byte == 0x01:      # double
            val = struct.unpack_from('<d', data, pos)[0]
            pos += 8
        elif type_byte == 0x02:    # string
            val, pos = _decode_bson_string(data, pos)
        elif type_byte == 0x03:    # embedded document
            val, pos = decode_bson_doc(data, pos)
        elif type_byte == 0x04:    # array
            arr_doc, pos = decode_bson_doc(data, pos)
            val = list(arr_doc.values())
        elif type_byte == 0x05:    # binary
            bin_len = struct.unpack_from('<i', data, pos)[0]
            subtype = data[pos + 4]
            val = BSONBinary(subtype, data[pos + 5:pos + 5 + bin_len])
            pos += 5 + bin_len
        elif type_byte == 0x07:    # ObjectId
            val = BSONObjectId(data[pos:pos + 12])
            pos += 12
        elif type_byte == 0x08:    # boolean
            val = data[pos] != 0
            pos += 1
        elif type_byte == 0x09:    # UTC datetime
            val = BSONDatetime(struct.unpack_from('<q', data, pos)[0])
            pos += 8
        elif type_byte == 0x0A:    # null
            val = None
        elif type_byte == 0x0B:    # regex
            pattern, pos = _decode_cstring(data, pos)
            options, pos = _decode_cstring(data, pos)
            val = BSONRegex(pattern, options)
        elif type_byte == 0x0D:    # JavaScript code
            code_str, pos = _decode_bson_string(data, pos)
            val = BSONCode(code_str)
        elif type_byte == 0x10:    # int32
            val = Int32(struct.unpack_from('<i', data, pos)[0])
            pos += 4
        elif type_byte == 0x11:    # timestamp
            inc = struct.unpack_from('<I', data, pos)[0]
            time_val = struct.unpack_from('<I', data, pos + 4)[0]
            val = BSONTimestamp(inc, time_val)
            pos += 8
        elif type_byte == 0x12:    # int64
            val = Int64(struct.unpack_from('<q', data, pos)[0])
            pos += 8
        elif type_byte == 0x13:    # decimal128
            val = BSONDecimal128(data[pos:pos + 16])
            pos += 16
        elif type_byte == 0xFF:    # min key
            val = BSONMinKey()
        elif type_byte == 0x7F:    # max key
            val = BSONMaxKey()
        else:
            raise ValueError(
                f"Unknown BSON type 0x{type_byte:02x} for key '{key}' "
                f"at pos {pos}")

        doc[key] = val

    return doc, end_pos


# =============================================================================
# BSON Encoder
# =============================================================================

def _encode_cstring(s):
    return s.encode('utf-8') + b'\x00'


def _encode_bson_string(s):
    encoded = s.encode('utf-8') + b'\x00'
    return struct.pack('<i', len(encoded)) + encoded


def _encode_element(key, val):
    kb = _encode_cstring(key)

    # bool must be checked before int (bool is a subclass of int in Python)
    if isinstance(val, bool):
        return b'\x08' + kb + (b'\x01' if val else b'\x00')
    if isinstance(val, Int32):
        return b'\x10' + kb + struct.pack('<i', val.value)
    if isinstance(val, Int64):
        return b'\x12' + kb + struct.pack('<q', val.value)
    if isinstance(val, float):
        return b'\x01' + kb + struct.pack('<d', val)
    if isinstance(val, str):
        return b'\x02' + kb + _encode_bson_string(val)
    if isinstance(val, OrderedDict):
        return b'\x03' + kb + encode_bson_doc(val)
    if isinstance(val, list):
        return b'\x04' + kb + _encode_array(val)
    if isinstance(val, BSONBinary):
        return (b'\x05' + kb + struct.pack('<i', len(val.data))
                + bytes([val.subtype]) + val.data)
    if isinstance(val, BSONObjectId):
        return b'\x07' + kb + val.data
    if isinstance(val, BSONDatetime):
        return b'\x09' + kb + struct.pack('<q', val.value)
    if val is None:
        return b'\x0A' + kb
    if isinstance(val, BSONRegex):
        return (b'\x0B' + kb + _encode_cstring(val.pattern)
                + _encode_cstring(val.options))
    if isinstance(val, BSONCode):
        return b'\x0D' + kb + _encode_bson_string(val.code)
    if isinstance(val, BSONTimestamp):
        return (b'\x11' + kb + struct.pack('<I', val.inc)
                + struct.pack('<I', val.time))
    if isinstance(val, BSONDecimal128):
        return b'\x13' + kb + val.data
    if isinstance(val, BSONMinKey):
        return b'\xFF' + kb
    if isinstance(val, BSONMaxKey):
        return b'\x7F' + kb

    raise ValueError(f"Cannot encode {type(val).__name__} for key '{key}'")


def encode_bson_doc(doc):
    """Encode an OrderedDict to BSON bytes (preserving field order)."""
    body = b''
    for key, val in doc.items():
        body += _encode_element(key, val)
    body += b'\x00'
    return struct.pack('<i', len(body) + 4) + body


def _encode_array(lst):
    doc = OrderedDict()
    for i, val in enumerate(lst):
        doc[str(i)] = val
    return encode_bson_doc(doc)


# =============================================================================
# FTDC Chunk Processing
# =============================================================================

FTDC_TYPE_METADATA = 0
FTDC_TYPE_METRIC_CHUNK = 1
FTDC_TYPE_PERIODIC_METADATA = 2


def iter_ftdc_documents(data):
    """Yield decoded BSON documents from raw FTDC file bytes."""
    pos = 0
    while pos + 4 <= len(data):
        doc_len = struct.unpack_from('<i', data, pos)[0]
        if doc_len <= 0:
            break
        if pos + doc_len > len(data):
            print(f"  Warning: truncated FTDC document at offset {pos}",
                  file=sys.stderr)
            break
        try:
            doc, _ = decode_bson_doc(data, pos)
            yield doc
        except Exception as e:
            print(f"  Warning: skipping FTDC document at offset {pos}: {e}",
                  file=sys.stderr)
        pos += doc_len


def _get_ftdc_type(doc):
    type_val = doc.get('type')
    if isinstance(type_val, Int32):
        return type_val.value
    if isinstance(type_val, Int64):
        return type_val.value
    if isinstance(type_val, int):
        return type_val
    return None


def decompress_metric_chunk(chunk_data):
    """Decompress an FTDC metric chunk.

    Returns (ref_bson_bytes, metrics_count, delta_count, delta_stream_bytes).
    """
    uncomp_len = struct.unpack_from('<I', chunk_data, 0)[0]
    compressed = chunk_data[4:]
    uncompressed = zlib.decompress(compressed)

    ref_doc_len = struct.unpack_from('<i', uncompressed, 0)[0]
    ref_bson = bytes(uncompressed[:ref_doc_len])

    pos = ref_doc_len
    metrics_count = struct.unpack_from('<I', uncompressed, pos)[0]
    pos += 4
    delta_count = struct.unpack_from('<I', uncompressed, pos)[0]
    pos += 4
    delta_stream = bytes(uncompressed[pos:])

    return ref_bson, metrics_count, delta_count, delta_stream


def recompress_metric_chunk(ref_bson, metrics_count, delta_count, delta_stream):
    """Re-compress with a modified reference doc; delta stream is verbatim."""
    payload = (ref_bson
               + struct.pack('<I', metrics_count)
               + struct.pack('<I', delta_count)
               + delta_stream)
    compressed = zlib.compress(payload)
    return struct.pack('<I', len(payload)) + compressed


# =============================================================================
# ObfuscatorRegistry: consistent mapping from original -> replacement
# =============================================================================

class ObfuscatorRegistry:

    def __init__(self):
        self.categories = {
            "hostname": {},
            "fqdn": {},
            "domain": {},
            "ip": {},
            "database": {},
            "collection": {},
            "replset": {},
            "shard": {},
            "user": {},
            "email": {},
            "path": {},
            "cert_subject": {},
            "org": {},
            "location": {},
            "java_class": {},
            "appname": {},
            "data": {},
        }
        self.counters = {cat: 0 for cat in self.categories}

    def _next_id(self, category):
        self.counters[category] += 1
        return self.counters[category]

    def get_or_create(self, category, original):
        if not original or original.strip() == "":
            return original

        mapping = self.categories[category]
        if original in mapping:
            return mapping[original]

        n = self._next_id(category)

        templates = {
            "hostname":     f"host{n}",
            "fqdn":         f"host{n}.example.com",
            "domain":       f"domain{n}.example.com",
            "ip":           f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}",
            "database":     f"database{n}",
            "collection":   f"collection{n}",
            "replset":      f"replset{n}",
            "shard":        f"shard{n}",
            "user":         f"user{n}",
            "email":        f"user{n}@example.com",
            "path":         f"/obfuscated/path{n}",
            "cert_subject": f"CN=cert{n}.example.com,O=Organization,L=City,ST=State,C=XX",
            "org":          f"Organization{n}",
            "location":     f"Location{n}",
            "java_class":   f"com.example.app.Class{n}",
            "appname":      f"app{n}",
            "data":         f"data_{n}",
        }

        replacement = templates.get(category, f"REDACTED_{category}_{n}")
        mapping[original] = replacement
        return replacement

    def get_mapping_report(self):
        report = {}
        for category, mapping in self.categories.items():
            if mapping:
                report[category] = dict(mapping)
        return report

    def load_from_file(self, path):
        """Seed the registry from a previously-written mapping file."""
        with open(path, 'r', encoding='utf-8') as f:
            mapping = json.load(f)
        for category, pairs in mapping.items():
            if category not in self.categories:
                continue
            for original, replacement in pairs.items():
                self.categories[category][original] = replacement
            max_id = 0
            for replacement in pairs.values():
                m = re.search(r'(\d+)', replacement)
                if m:
                    max_id = max(max_id, int(m.group(1)))
            self.counters[category] = max(self.counters[category], max_id)


# =============================================================================
# MongoObfuscator — unified log + FTDC obfuscation
# =============================================================================

class MongoObfuscator:

    def __init__(self):
        self.registry = ObfuscatorRegistry()
        self._all_sensitive_strings = set()

    # ----- Registration -----

    def _register(self, category, value):
        if not value or len(value) < 2:
            return
        if category == "hostname" and len(value) < 4:
            return
        self.registry.get_or_create(category, value)
        self._all_sensitive_strings.add(value)

    # ----- Infrastructure discovery (key-based) -----

    def _discover_value(self, key, val):
        """Classify and register a JSON attribute value based on its key."""
        if not isinstance(val, str) or not val.strip():
            return
        val = val.strip()

        if key in REPLSET_KEYS:
            self._register("replset", val)
            return
        if key in SHARD_KEYS:
            self._register("shard", val)
            return
        if key in DATABASE_KEYS:
            if val not in INTERNAL_DBS and val != "$external":
                self._register("database", val)
            return
        if key in COLLECTION_KEYS:
            if not val.startswith("system.") and not val.startswith("$"):
                self._register("collection", val)
            return
        if key in NAMESPACE_KEYS:
            if key == "affectedNamespaces":
                for ns in val.replace("[", "").replace("]", "").split(","):
                    ns = ns.strip().strip('"').strip("'")
                    if ns:
                        self._discover_namespace(ns)
            else:
                self._discover_namespace(val)
            return
        if key in USER_KEYS:
            if "@" in val:
                self._register("email", val)
                self._register("domain", val.split("@")[1])
            else:
                self._register("user", val)
            return
        if key in CERT_SUBJECT_KEYS:
            self._discover_cert_subject(val)
            return
        if key in PATH_KEYS:
            self._discover_path(val)
            return
        if key in HOST_KEYS:
            self._discover_host_value(val)
            return
        if key in REMOTE_LOCAL_KEYS:
            self._discover_host_value(val)
            return
        if key in CLIENT_KEYS:
            if not re.fullmatch(r'conn\d+', val):
                self._discover_host_value(val)
            return
        if key in CONN_STRING_KEYS:
            self._discover_connstring(val)
            return
        if key in APP_NAME_KEYS:
            self._register("appname", val)
            return
        if key in HOST_LIST_KEYS:
            for part in val.replace("[", "").replace("]", "").split(","):
                part = part.strip().strip('"').strip("'")
                if part:
                    self._discover_host_value(part)
            return
        if key == "bindIp":
            for part in val.split(","):
                part = part.strip()
                if part and not part.startswith("127.") and part != "0.0.0.0":
                    if RE_IP.fullmatch(part):
                        self._register("ip", part)
                    else:
                        self._discover_host_value(part)
            return
        if key == "servers":
            for server in val.split(","):
                server = server.strip()
                if server:
                    self._discover_host_value(server)
            return
        if key in FREETEXT_KEYS:
            self._discover_freetext(val)
            self._discover_bson_document(val)
            return

        self._discover_freetext_light(val)

    def _discover_namespace(self, ns):
        if ns in KNOWN_NON_DOMAINS:
            return
        parts = ns.split(".", 1)
        if len(parts) == 2:
            db, coll = parts
            if db not in INTERNAL_DBS:
                self._register("database", db)
            if (not coll.startswith("system.") and not coll.startswith("$")
                    and coll not in ("startup_log",)):
                self._register("collection", coll)

    def _discover_host_value(self, val):
        host = val
        if ":" in val and not val.startswith("["):
            host, _ = val.rsplit(":", 1)
        if RE_IP.fullmatch(host):
            if not host.startswith("127.") and host != "0.0.0.0":
                self._register("ip", host)
        elif "." in host:
            self._register("fqdn", host)
            parts = host.split(".")
            if len(parts) >= 3:
                self._register("domain", ".".join(parts[-2:]))
            self._register("hostname", parts[0])
        else:
            self._register("hostname", host)

    def _discover_cert_subject(self, val):
        self._register("cert_subject", val)
        for part in val.split(","):
            part = part.strip()
            if part.startswith("CN="):
                cn = part[3:]
                if "." in cn:
                    self._discover_host_value(cn)
                else:
                    self._register("hostname", cn)
            elif part.startswith("O="):
                self._register("org", part[2:])
            elif part.startswith("L="):
                self._register("location", part[2:])
            elif part.startswith("ST="):
                self._register("location", part[3:])
            elif part.startswith("OU="):
                self._register("org", part[3:])

    def _discover_path(self, val):
        if val and val.startswith("/"):
            self._register("path", val)

    def _discover_connstring(self, val):
        match = re.search(r'mongodb(?:\+srv)?://(.+?)(?:/(.*))?$', val)
        if match:
            for hp in match.group(1).split(","):
                self._discover_host_value(hp.strip())
            db_part = match.group(2)
            if db_part:
                db_name = db_part.split("?")[0]
                if db_name and db_name not in INTERNAL_DBS:
                    self._register("database", db_name)
                if "?" in db_part:
                    query = db_part.split("?", 1)[1]
                    for param in query.split("&"):
                        if param.startswith("replicaSet="):
                            rs_name = param.split("=", 1)[1]
                            if rs_name:
                                self._register("replset", rs_name)
        if not match and "://" in val:
            uri_match = re.search(r'://([^/\s?]+)', val)
            if uri_match:
                for hp in uri_match.group(1).split(","):
                    self._discover_host_value(hp.strip())

    # ----- Freetext scanning (regex-based) -----

    def _discover_freetext(self, text):
        for match in RE_EMAIL.finditer(text):
            self._register("email", match.group())
            self._register("domain", match.group().split("@")[1])

        for match in RE_IP.finditer(text):
            ip = match.group()
            if not ip.startswith("127.") and ip != "0.0.0.0":
                self._register("ip", ip)

        for match in RE_LDAP_DN_COMPONENT.finditer(text):
            prefix = text[match.start():match.start()+3].upper()
            value = match.group(1).strip()
            if not value or len(value) < 2:
                continue
            if prefix.startswith("DC"):
                if value.lower() not in ("com", "net", "org", "edu", "gov"):
                    self._register("org", value)
            elif prefix.startswith("OU"):
                self._register("org", value)
            elif prefix.startswith("CN"):
                if "." in value:
                    self._discover_host_value(value)
                elif len(value) >= 4:
                    self._register("hostname", value)
            elif prefix.startswith("O="):
                self._register("org", value)
            elif prefix.startswith("L="):
                self._register("location", value)
            elif prefix.startswith("ST"):
                self._register("location", value)

        for match in RE_FQDN.finditer(text):
            fqdn = match.group()
            if fqdn.endswith((".mongodb.org", ".kernel.org", ".example.com")):
                continue
            if re.match(r'^\d+\.\d+\.\d+', fqdn):
                continue
            if fqdn in KNOWN_NON_DOMAINS:
                continue
            parts = fqdn.split(".")
            if parts[0] in INTERNAL_DBS:
                continue
            if any(p[0].isupper() for p in parts if p):
                continue
            if len(parts) > 4:
                continue
            self._register("fqdn", fqdn)
            if len(parts) >= 3:
                self._register("domain", ".".join(parts[-2:]))
            self._register("hostname", parts[0])

        for match in RE_JAVA_CLASS.finditer(text):
            self._register("java_class", match.group())

    def _discover_freetext_light(self, text):
        if not isinstance(text, str):
            return
        if RE_IP.search(text) or RE_EMAIL.search(text) or RE_FQDN.search(text):
            self._discover_freetext(text)

    # ----- Embedded BSON document scanning (generic, for log lines) -----

    def _is_safe_bson_value(self, key, value):
        if not value or len(value) < 2:
            return True
        if key in BSON_STRUCTURAL_KEYS:
            return True
        if value in BSON_SAFE_VALUES:
            return True
        if len(value) == 2 and value.upper() in COUNTRY_CODES:
            return True
        if len(value) == 3 and value.upper() in CURRENCY_CODES:
            return True
        if RE_PURE_NUMBER.match(value):
            return True
        if RE_HEX.match(value):
            return True
        if RE_UUID_LIKE.match(value):
            return True
        if len(value) == 1:
            return True
        if re.match(r'^(ObjectId|UUID|BinData|Timestamp|Date)\b', value):
            return True
        return False

    def _discover_bson_document(self, text):
        if '": "' not in text and ': "' not in text:
            return
        for match in RE_BSON_STRING_FIELD.finditer(text):
            key = match.group(1)
            value = match.group(2)
            if self._is_safe_bson_value(key, value):
                continue

            if key == "ns" or (key == "namespace" and "." in value):
                self._discover_namespace(value)
                continue
            if key in ("host", "hostAndPort", "remote", "local", "peer",
                        "addr", "address", "server", "primary", "target"):
                self._discover_host_value(value)
                continue
            if key in ("shard", "shardId", "fromShard", "toShard",
                        "donorShardId", "recipientShardId"):
                self._register("shard", value)
                continue
            if "@" in value and RE_EMAIL.fullmatch(value):
                self._register("email", value)
                self._register("domain", value.split("@")[1])
                continue
            if RE_IP.fullmatch(value):
                if not value.startswith("127.") and value != "0.0.0.0":
                    self._register("ip", value)
                continue
            if RE_JAVA_CLASS.fullmatch(value):
                self._register("java_class", value)
                continue
            if value.startswith("/"):
                self._register("path", value)
                continue
            if RE_FQDN.fullmatch(value) and "." in value:
                self._discover_host_value(value)
                continue
            self._register("data", value)

    # ----- Deep walk for JSON objects (log lines) -----

    def deep_discover(self, obj, depth=0):
        if depth > 20:
            return
        if isinstance(obj, dict):
            if "members" in obj and isinstance(obj["members"], list):
                for member in obj["members"]:
                    if isinstance(member, dict) and "host" in member:
                        self._discover_host_value(str(member["host"]))
            if "options" in obj and isinstance(obj["options"], dict):
                self._discover_options(obj["options"])

            for key, val in obj.items():
                if key in SKIP_KEYS:
                    continue
                self._discover_value(key, val)
                if isinstance(val, (dict, list)):
                    self.deep_discover(val, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self.deep_discover(item, depth + 1)
        elif isinstance(obj, str):
            self._discover_freetext_light(obj)

    def _discover_options(self, options):
        if not isinstance(options, dict):
            return

        net = options.get("net", {})
        if isinstance(net, dict):
            bind_ip = net.get("bindIp", "")
            if bind_ip:
                self._discover_value("bindIp", bind_ip)
            tls = net.get("tls", {})
            if isinstance(tls, dict):
                for k in ("CAFile", "certificateKeyFile", "clusterFile"):
                    if k in tls:
                        self._discover_path(tls[k])

        repl = options.get("replication", {})
        if isinstance(repl, dict) and repl.get("replSetName"):
            self._register("replset", repl["replSetName"])

        storage = options.get("storage", {})
        if isinstance(storage, dict) and storage.get("dbPath"):
            self._discover_path(storage["dbPath"])

        syslog = options.get("systemLog", {})
        if isinstance(syslog, dict) and syslog.get("path"):
            self._discover_path(syslog["path"])

        security = options.get("security", {})
        if isinstance(security, dict):
            ldap = security.get("ldap", {})
            if isinstance(ldap, dict):
                if ldap.get("servers"):
                    self._discover_value("servers", ldap["servers"])
                bind = ldap.get("bind", {})
                if isinstance(bind, dict) and bind.get("queryUser"):
                    self._discover_value("queryUser", bind["queryUser"])
                if ldap.get("userToDNMapping"):
                    self._discover_freetext(ldap["userToDNMapping"])

        pm = options.get("processManagement", {})
        if isinstance(pm, dict) and pm.get("pidFilePath"):
            self._discover_path(pm["pidFilePath"])

        config = options.get("config", "")
        if isinstance(config, str) and config.startswith("/"):
            self._discover_path(config)

    def _discover_command_data(self, obj, depth=0):
        if depth > 10:
            return
        if isinstance(obj, dict):
            for cmd_key in ("find", "aggregate", "insert", "update", "delete",
                            "findAndModify", "count", "distinct", "getMore",
                            "create", "drop", "renameCollection",
                            "createIndexes", "dropIndexes", "collMod",
                            "explain"):
                if cmd_key in obj and isinstance(obj[cmd_key], str):
                    coll = obj[cmd_key]
                    if not coll.startswith("system.") and not coll.startswith("$"):
                        self._register("collection", coll)
            if "to" in obj and isinstance(obj["to"], str) and "." in obj["to"]:
                self._discover_namespace(obj["to"])
            for val in obj.values():
                if isinstance(val, (dict, list)):
                    self._discover_command_data(val, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._discover_command_data(item, depth + 1)

    # ----- Deep walk for BSON documents (FTDC) -----

    def deep_discover_bson(self, doc, depth=0):
        """Recursively walk a BSON document (OrderedDict from FTDC) and
        register all sensitive string values.

        Handles FTDC-specific structures: member arrays with ``name`` as host,
        host/passive/arbiter arrays in replication sections, etc.
        """
        if depth > 20 or not isinstance(doc, (dict, OrderedDict)):
            return

        if "members" in doc and isinstance(doc["members"], list):
            for member in doc["members"]:
                if isinstance(member, (dict, OrderedDict)):
                    for hk in ("host", "name"):
                        if hk in member and isinstance(member[hk], str):
                            self._discover_host_value(member[hk])

        if "options" in doc and isinstance(doc["options"], (dict, OrderedDict)):
            self._discover_options(doc["options"])

        for key, val in doc.items():
            if key in SKIP_KEYS:
                continue
            if isinstance(val, str):
                self._discover_value(key, val)
            elif isinstance(val, (dict, OrderedDict)):
                self.deep_discover_bson(val, depth + 1)
            elif isinstance(val, list):
                self._discover_bson_list(key, val, depth + 1)

    def _discover_bson_list(self, parent_key, lst, depth):
        if depth > 20:
            return
        if parent_key in HOST_LIST_KEYS:
            for item in lst:
                if isinstance(item, str):
                    self._discover_host_value(item)
            return
        if parent_key in NAMESPACE_KEYS:
            for item in lst:
                if isinstance(item, str):
                    self._discover_namespace(item)
            return
        for item in lst:
            if isinstance(item, (dict, OrderedDict)):
                self.deep_discover_bson(item, depth)
            elif isinstance(item, str):
                self._discover_freetext_light(item)
            elif isinstance(item, list):
                self._discover_bson_list(parent_key, item, depth + 1)

    # ----- Replacement engine -----

    def build_replacement_table(self):
        replacements = []
        for category, mapping in self.registry.categories.items():
            for original, obfuscated in mapping.items():
                replacements.append((original, obfuscated))
        replacements.sort(key=lambda x: len(x[0]), reverse=True)
        return replacements

    def _apply_replacements(self, text, replacements):
        for original, obfuscated in replacements:
            if original in text:
                text = text.replace(original, obfuscated)
        return text

    def _obfuscate_bson_doc(self, doc, replacements):
        """Return a copy of doc with all string values obfuscated."""
        if isinstance(doc, OrderedDict):
            result = OrderedDict()
            for key, val in doc.items():
                if isinstance(val, str):
                    result[key] = self._apply_replacements(val, replacements)
                elif isinstance(val, (OrderedDict, list)):
                    result[key] = self._obfuscate_bson_doc(val, replacements)
                else:
                    result[key] = val
            return result
        if isinstance(doc, list):
            out = []
            for item in doc:
                if isinstance(item, str):
                    out.append(self._apply_replacements(item, replacements))
                elif isinstance(item, (OrderedDict, list)):
                    out.append(self._obfuscate_bson_doc(item, replacements))
                else:
                    out.append(item)
            return out
        return doc

    # ----- Log file processing -----

    def _discover_log_file(self, path):
        print(f"  [log]  {path}", file=sys.stderr)
        count = 0
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                count += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    self.deep_discover(obj)
                    attr = obj.get("attr", {})
                    if isinstance(attr, dict):
                        for cmd_key in ("command", "cmdObj",
                                        "originatingCommand"):
                            if cmd_key in attr and isinstance(
                                    attr[cmd_key], dict):
                                self._discover_command_data(attr[cmd_key])
                except json.JSONDecodeError:
                    self._discover_freetext(line)
        print(f"           {count} lines", file=sys.stderr)
        return count

    def _replace_log_file(self, input_path, output_path, replacements):
        print(f"  [log]  {input_path} -> {output_path}", file=sys.stderr)
        with open(input_path, "r", encoding="utf-8", errors="replace") as fin, \
             open(output_path, "w", encoding="utf-8") as fout:
            for line in fin:
                fout.write(self._apply_replacements(line, replacements))

    # ----- FTDC file processing -----

    def _discover_ftdc_file(self, path):
        print(f"  [ftdc] {path}", file=sys.stderr)
        data = _read_binary(path)
        count = 0
        for doc in iter_ftdc_documents(data):
            ftdc_type = _get_ftdc_type(doc)

            if ftdc_type == FTDC_TYPE_METADATA:
                inner = doc.get('doc')
                if isinstance(inner, (dict, OrderedDict)):
                    self.deep_discover_bson(inner)

            elif ftdc_type == FTDC_TYPE_METRIC_CHUNK:
                binary = doc.get('data')
                if isinstance(binary, BSONBinary):
                    try:
                        ref_bson, _, _, _ = decompress_metric_chunk(
                            binary.data)
                        ref_doc, _ = decode_bson_doc(ref_bson)
                        self.deep_discover_bson(ref_doc)
                    except Exception as e:
                        print(f"    Warning: chunk decompress failed: {e}",
                              file=sys.stderr)

            elif ftdc_type == FTDC_TYPE_PERIODIC_METADATA:
                inner = doc.get('doc')
                if isinstance(inner, (dict, OrderedDict)):
                    self.deep_discover_bson(inner)

            count += 1
        print(f"           {count} BSON documents", file=sys.stderr)
        return count

    def _replace_ftdc_file(self, input_path, output_path, replacements):
        print(f"  [ftdc] {input_path} -> {output_path}", file=sys.stderr)
        data = _read_binary(input_path)
        with open(output_path, 'wb') as fout:
            for doc in iter_ftdc_documents(data):
                ftdc_type = _get_ftdc_type(doc)

                if ftdc_type == FTDC_TYPE_METADATA:
                    inner = doc.get('doc')
                    if isinstance(inner, (dict, OrderedDict)):
                        doc = OrderedDict(doc)
                        doc['doc'] = self._obfuscate_bson_doc(
                            inner, replacements)

                elif ftdc_type == FTDC_TYPE_METRIC_CHUNK:
                    binary = doc.get('data')
                    if isinstance(binary, BSONBinary):
                        try:
                            ref_bson, mc, dc, deltas = \
                                decompress_metric_chunk(binary.data)
                            ref_doc, _ = decode_bson_doc(ref_bson)
                            mod_ref = self._obfuscate_bson_doc(
                                ref_doc, replacements)
                            mod_bson = encode_bson_doc(mod_ref)
                            new_chunk = recompress_metric_chunk(
                                mod_bson, mc, dc, deltas)
                            doc = OrderedDict(doc)
                            doc['data'] = BSONBinary(binary.subtype,
                                                     new_chunk)
                        except Exception as e:
                            print(f"    Warning: chunk recompress failed: {e}",
                                  file=sys.stderr)

                elif ftdc_type == FTDC_TYPE_PERIODIC_METADATA:
                    inner = doc.get('doc')
                    if isinstance(inner, (dict, OrderedDict)):
                        doc = OrderedDict(doc)
                        doc['doc'] = self._obfuscate_bson_doc(
                            inner, replacements)

                fout.write(encode_bson_doc(doc))

    # ----- Main orchestration -----

    def process(self, file_list, input_root, output_root, mapping_path):
        """Two-pass processing of all log and FTDC files.

        Pass 1 — Discovery: scan every file and register sensitive values.
        Pass 2 — Replacement: re-read, obfuscate, and write to output_root
                 preserving the directory structure relative to input_root.
        """
        os.makedirs(output_root, exist_ok=True)

        log_files = [(p, t) for p, t in file_list if t == "log"]
        ftdc_files = [(p, t) for p, t in file_list if t == "ftdc"]

        total_files = len(file_list)
        print(f"Found {total_files} file(s): "
              f"{len(log_files)} log, {len(ftdc_files)} FTDC",
              file=sys.stderr)
        print(file=sys.stderr)

        # Pass 1: Discovery
        print("Pass 1: Discovering sensitive values...", file=sys.stderr)
        for path, ftype in file_list:
            if ftype == "log":
                self._discover_log_file(path)
            else:
                self._discover_ftdc_file(path)

        print(file=sys.stderr)
        for cat, mapping in self.registry.categories.items():
            if mapping:
                print(f"  {cat}: {len(mapping)} unique values",
                      file=sys.stderr)

        replacements = self.build_replacement_table()
        print(f"  Total replacements: {len(replacements)}", file=sys.stderr)
        print(file=sys.stderr)

        # Pass 2: Replacement
        print("Pass 2: Writing obfuscated files...", file=sys.stderr)
        for path, ftype in file_list:
            out_path = _compute_output_path(path, input_root, output_root,
                                            ftype)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            if ftype == "log":
                self._replace_log_file(path, out_path, replacements)
            else:
                self._replace_ftdc_file(path, out_path, replacements)

        # Write shared mapping
        print(file=sys.stderr)
        print(f"Writing mapping to {mapping_path}...", file=sys.stderr)
        with open(mapping_path, "w", encoding="utf-8") as f:
            json.dump(self.registry.get_mapping_report(), f, indent=2,
                      ensure_ascii=False)

        print(f"Done. {total_files} file(s) obfuscated.", file=sys.stderr)


# =============================================================================
# File classification, scanning, and output path computation
# =============================================================================

def _read_binary(path):
    with open(path, 'rb') as f:
        return f.read()


def _classify_file(path):
    """Return 'log', 'ftdc', or None (skip)."""
    basename = os.path.basename(path)
    parent = os.path.basename(os.path.dirname(path))

    # Skip hidden files, mapping files, already-obfuscated output
    if basename.startswith("."):
        return None
    if basename == "cluster_mapping.json":
        return None
    if "_obfuscated" in basename or "_obfuscated" in path:
        return None

    # Skip archives and compressed files
    for ext in (".tar.gz", ".tgz", ".tar", ".gz", ".zip", ".bz2", ".xz",
                ".7z", ".rar"):
        if basename.endswith(ext):
            return None

    # FTDC patterns
    if parent == "diagnostic.data":
        return "ftdc"
    if basename.endswith(".ftdc"):
        return "ftdc"
    if basename.startswith("metrics.") or basename == "metrics":
        return "ftdc"

    # Log patterns
    if basename.endswith(".log"):
        return "log"

    # Binary heuristic: null bytes in first 256 bytes → FTDC
    try:
        with open(path, 'rb') as f:
            header = f.read(256)
        if b'\x00' in header:
            return "ftdc"
    except (OSError, IOError):
        return None

    # Default to log for text files
    return "log"


def _scan_directory(root, exclude_dir=None):
    """Recursively scan a directory for log and FTDC files.

    Returns a list of (absolute_path, file_type) tuples.
    """
    file_list = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip hidden directories and the output directory
        dirnames[:] = [d for d in dirnames
                       if not d.startswith(".")
                       and d != "obfuscated"
                       and (exclude_dir is None
                            or os.path.abspath(os.path.join(dirpath, d))
                            != exclude_dir)]
        for fname in sorted(filenames):
            fpath = os.path.join(dirpath, fname)
            ftype = _classify_file(fpath)
            if ftype:
                file_list.append((os.path.abspath(fpath), ftype))
    return file_list


def _resolve_inputs(inputs, exclude_dir=None):
    """Expand CLI inputs into a flat list of (abs_path, file_type) tuples
    and determine the common input root for directory structure mirroring.

    Returns (file_list, input_root).
    """
    import glob as globmod
    file_list = []
    input_dirs = []

    for entry in inputs:
        if os.path.isdir(entry):
            abs_entry = os.path.abspath(entry)
            input_dirs.append(abs_entry)
            file_list.extend(_scan_directory(abs_entry, exclude_dir))
        elif "*" in entry or "?" in entry:
            for match in sorted(globmod.glob(entry)):
                if os.path.isfile(match):
                    ftype = _classify_file(match)
                    if ftype:
                        file_list.append((os.path.abspath(match), ftype))
                elif os.path.isdir(match):
                    abs_match = os.path.abspath(match)
                    input_dirs.append(abs_match)
                    file_list.extend(_scan_directory(abs_match, exclude_dir))
        elif os.path.isfile(entry):
            ftype = _classify_file(entry)
            if ftype:
                file_list.append((os.path.abspath(entry), ftype))
        else:
            print(f"  Warning: {entry} not found, skipping",
                  file=sys.stderr)

    # Deduplicate
    seen = set()
    deduped = []
    for item in file_list:
        if item[0] not in seen:
            seen.add(item[0])
            deduped.append(item)

    # Determine input root for structure mirroring
    if input_dirs:
        input_root = os.path.commonpath(input_dirs)
    elif deduped:
        input_root = os.path.commonpath([p for p, _ in deduped])
        # If all files are in the same directory, use that directory
        if os.path.isfile(input_root):
            input_root = os.path.dirname(input_root)
    else:
        input_root = os.getcwd()

    return deduped, input_root


def _compute_output_path(input_path, input_root, output_root, file_type):
    """Mirror the input directory structure under output_root.

    Log files:  mongod.log  ->  mongod_obfuscated.log
    FTDC files: diagnostic.data/metrics.XXX  ->  diagnostic.data/metrics.XXX
                (exact same relative path — the output root IS the marker)
    """
    rel = os.path.relpath(input_path, input_root)
    dirname = os.path.dirname(rel)
    basename = os.path.basename(rel)

    if file_type == "ftdc":
        # Keep the exact relative path unchanged
        return os.path.join(output_root, rel)
    else:
        if basename.endswith(".log"):
            out_name = basename[:-4] + "_obfuscated.log"
        else:
            out_name = basename + "_obfuscated"
        return os.path.join(output_root, dirname, out_name)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Obfuscate sensitive data in MongoDB log files and FTDC "
                    "diagnostic files with coherent, consistent replacements "
                    "across an entire cluster. Recreates the input directory "
                    "structure in the output."
    )
    parser.add_argument(
        "input", nargs="+",
        help="One or more directories, log files, FTDC files, or glob "
             "patterns. Directories are scanned recursively for *.log "
             "files and diagnostic.data/ FTDC files."
    )
    parser.add_argument(
        "-o", "--output-dir",
        help="Root directory for obfuscated output (default: "
             "<input>_obfuscated/)"
    )
    parser.add_argument(
        "-m", "--mapping",
        help="Path for the shared mapping JSON file "
             "(default: <output-dir>/cluster_mapping.json)"
    )
    parser.add_argument(
        "--load-mapping",
        help="Load an existing mapping to continue a prior run or merge "
             "with another obfuscation pass"
    )

    args = parser.parse_args()

    # Determine output directory early so we can exclude it from scanning.
    # For the default we need the input root, so do a quick resolve first.
    if args.output_dir:
        output_root = os.path.abspath(args.output_dir)
    else:
        # Peek at the first input to derive the root
        first = args.input[0]
        if os.path.isdir(first):
            output_root = os.path.join(os.path.abspath(first), "obfuscated")
        else:
            output_root = os.path.join(
                os.path.dirname(os.path.abspath(first)), "obfuscated")

    file_list, input_root = _resolve_inputs(args.input,
                                            exclude_dir=output_root)
    if not file_list:
        print("Error: no log or FTDC files found.", file=sys.stderr)
        sys.exit(1)

    # Re-derive default output_root now that we have the real input_root
    if not args.output_dir:
        output_root = os.path.join(input_root, "obfuscated")
    os.makedirs(output_root, exist_ok=True)

    mapping_path = (args.mapping
                    or os.path.join(output_root, "cluster_mapping.json"))

    print(f"Input root:   {input_root}", file=sys.stderr)
    print(f"Output root:  {output_root}", file=sys.stderr)
    print(f"Mapping file: {mapping_path}", file=sys.stderr)
    print(file=sys.stderr)

    obfuscator = MongoObfuscator()

    if args.load_mapping:
        print(f"Loading existing mapping from {args.load_mapping}...",
              file=sys.stderr)
        obfuscator.registry.load_from_file(args.load_mapping)
        print(file=sys.stderr)

    obfuscator.process(file_list, input_root, output_root, mapping_path)


if __name__ == "__main__":
    main()

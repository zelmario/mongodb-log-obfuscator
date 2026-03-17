#!/usr/bin/env python3
"""
MongoDB Log Obfuscator

Reads a MongoDB structured JSON log file and produces:
1. An obfuscated log file with consistent replacements
2. A mapping file (original -> obfuscated) for reference

Usage:
    python mongodb_log_obfuscator.py <input.log> [-o output.log] [-m mapping.json]
"""

import argparse
import json
import os
import re
import sys


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

# Keys whose values are host lists (comma or otherwise separated)
HOST_LIST_KEYS = {"addresses", "failedHosts", "nodes", "configServers",
                  "listenAddrs", "attemptedHosts"}

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
            "data": {},  # generic catch-all for any business/document data
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


# =============================================================================
# MongoLogObfuscator
# =============================================================================

class MongoLogObfuscator:

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
            # Some namespace keys hold multiple namespaces as a list string
            if key == "affectedNamespaces":
                # May be comma-separated or logged as array; handle string form
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
                # Extract replicaSet from query parameters
                if "?" in db_part:
                    query = db_part.split("?", 1)[1]
                    for param in query.split("&"):
                        if param.startswith("replicaSet="):
                            rs_name = param.split("=", 1)[1]
                            if rs_name:
                                self._register("replset", rs_name)
        # Also handle non-standard URI formats (ldap://, etc.)
        if not match and "://" in val:
            uri_match = re.search(r'://([^/\s?]+)', val)
            if uri_match:
                for hp in uri_match.group(1).split(","):
                    self._discover_host_value(hp.strip())

    # ----- Freetext scanning (regex-based) -----

    def _discover_freetext(self, text):
        """Scan free text for IPs, FQDNs, emails, LDAP DNs, Java classes."""
        for match in RE_EMAIL.finditer(text):
            self._register("email", match.group())
            self._register("domain", match.group().split("@")[1])

        for match in RE_IP.finditer(text):
            ip = match.group()
            if not ip.startswith("127.") and ip != "0.0.0.0":
                self._register("ip", ip)

        # LDAP DN components
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

        # FQDNs
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

        # Java class names
        for match in RE_JAVA_CLASS.finditer(text):
            self._register("java_class", match.group())

    def _discover_freetext_light(self, text):
        """Light freetext scan for unrecognized keys — triggers full scan
        if the value looks like it might contain network/identity data."""
        if not isinstance(text, str):
            return
        if RE_IP.search(text) or RE_EMAIL.search(text) or RE_FQDN.search(text):
            self._discover_freetext(text)

    # ----- Embedded BSON document scanning (generic) -----

    def _is_safe_bson_value(self, key, value):
        """Determine if a string value from a BSON document is safe (not PII).

        Returns True if the value should NOT be obfuscated.
        """
        # Empty / too short
        if not value or len(value) < 2:
            return True

        # Structural BSON keys — their values are operational
        if key in BSON_STRUCTURAL_KEYS:
            return True

        # Known safe string values
        if value in BSON_SAFE_VALUES:
            return True

        # Country codes (2-letter)
        if len(value) == 2 and value.upper() in COUNTRY_CODES:
            return True

        # Currency codes (3-letter)
        if len(value) == 3 and value.upper() in CURRENCY_CODES:
            return True

        # Pure numbers (including decimals, negatives)
        if RE_PURE_NUMBER.match(value):
            return True

        # Hex strings (ObjectIds, hashes)
        if RE_HEX.match(value):
            return True

        # UUID-like
        if RE_UUID_LIKE.match(value):
            return True

        # Single character
        if len(value) == 1:
            return True

        # Looks like a BSON type value: ObjectId('...'), UUID('...'), etc.
        # These are already inside quotes as their string representation
        if re.match(r'^(ObjectId|UUID|BinData|Timestamp|Date)\b', value):
            return True

        return False

    def _discover_bson_document(self, text):
        """Extract ALL string values from embedded BSON documents and obfuscate them.

        This handles any schema — no hardcoded field names needed.
        Works on stringified BSON like:
            o: { name: "ACME Corp", city: "Springfield", dealId: "12345", ... }
        """
        # Only process text that looks like it contains embedded documents
        if '": "' not in text and ': "' not in text:
            return

        for match in RE_BSON_STRING_FIELD.finditer(text):
            key = match.group(1)
            value = match.group(2)

            # Skip safe values
            if self._is_safe_bson_value(key, value):
                continue

            # Classify by content pattern for better replacement names

            # Namespace pattern (db.collection)
            if key == "ns" or (key == "namespace" and "." in value):
                self._discover_namespace(value)
                continue

            # Host/network patterns
            if key in ("host", "hostAndPort", "remote", "local", "peer",
                        "addr", "address", "server", "primary", "target"):
                self._discover_host_value(value)
                continue

            # Shard names in embedded BSON
            if key in ("shard", "shardId", "fromShard", "toShard",
                        "donorShardId", "recipientShardId"):
                self._register("shard", value)
                continue

            # Email pattern
            if "@" in value and RE_EMAIL.fullmatch(value):
                self._register("email", value)
                self._register("domain", value.split("@")[1])
                continue

            # IP pattern
            if RE_IP.fullmatch(value):
                if not value.startswith("127.") and value != "0.0.0.0":
                    self._register("ip", value)
                continue

            # Java class pattern
            if RE_JAVA_CLASS.fullmatch(value):
                self._register("java_class", value)
                continue

            # Path pattern
            if value.startswith("/"):
                self._register("path", value)
                continue

            # FQDN pattern
            if RE_FQDN.fullmatch(value) and "." in value:
                self._discover_host_value(value)
                continue

            # Everything else: generic data obfuscation
            self._register("data", value)

    # ----- Deep walk for nested JSON objects -----

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
        """Walk the startup options/config block."""
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
        """Scan command objects for collection names and other sensitive data."""
        if depth > 10:
            return
        if isinstance(obj, dict):
            # Collection name extraction from MongoDB commands
            for cmd_key in ("find", "aggregate", "insert", "update", "delete",
                            "findAndModify", "count", "distinct", "getMore",
                            "create", "drop", "renameCollection",
                            "createIndexes", "dropIndexes", "collMod",
                            "explain"):
                if cmd_key in obj and isinstance(obj[cmd_key], str):
                    coll = obj[cmd_key]
                    if not coll.startswith("system.") and not coll.startswith("$"):
                        self._register("collection", coll)
            # "to" in renameCollection contains a namespace
            if "to" in obj and isinstance(obj["to"], str) and "." in obj["to"]:
                self._discover_namespace(obj["to"])
            for val in obj.values():
                if isinstance(val, (dict, list)):
                    self._discover_command_data(val, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._discover_command_data(item, depth + 1)

    # ----- Replacement engine -----

    def build_replacement_table(self):
        replacements = []
        for category, mapping in self.registry.categories.items():
            for original, obfuscated in mapping.items():
                replacements.append((original, obfuscated))
        # Longest first to avoid partial matches
        replacements.sort(key=lambda x: len(x[0]), reverse=True)
        return replacements

    def obfuscate_line(self, line, replacements):
        for original, obfuscated in replacements:
            if original in line:
                line = line.replace(original, obfuscated)
        return line

    # ----- Main entry points -----

    def _discover_file(self, input_path):
        """Pass 1 for a single file: discover all sensitive values."""
        print(f"  Scanning {input_path}...", file=sys.stderr)
        line_count = 0
        with open(input_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_count += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    self.deep_discover(obj)
                    attr = obj.get("attr", {})
                    if isinstance(attr, dict):
                        for cmd_key in ("command", "cmdObj", "originatingCommand"):
                            if cmd_key in attr and isinstance(attr[cmd_key], dict):
                                self._discover_command_data(attr[cmd_key])
                except json.JSONDecodeError:
                    self._discover_freetext(line)
        print(f"    {line_count} lines", file=sys.stderr)
        return line_count

    def _replace_file(self, input_path, output_path, replacements):
        """Pass 2 for a single file: apply replacements and write output."""
        print(f"  {input_path} -> {output_path}", file=sys.stderr)
        with open(input_path, "r", encoding="utf-8", errors="replace") as fin, \
             open(output_path, "w", encoding="utf-8") as fout:
            for line in fin:
                fout.write(self.obfuscate_line(line, replacements))

    def process(self, input_paths, output_dir, mapping_path):
        """Process one or more log files with a single shared registry.

        All files are discovered first (Pass 1), building one unified mapping.
        Then all files are replaced (Pass 2) using that shared mapping.
        This guarantees coherent obfuscation across an entire cluster.
        """
        # Pass 1: Discovery across ALL files
        print(f"Pass 1: Discovering sensitive values across "
              f"{len(input_paths)} file(s)...", file=sys.stderr)
        total_lines = 0
        for path in input_paths:
            total_lines += self._discover_file(path)

        print(f"  Total: {total_lines} lines across {len(input_paths)} file(s)",
              file=sys.stderr)
        for cat, mapping in self.registry.categories.items():
            if mapping:
                print(f"  {cat}: {len(mapping)} unique values", file=sys.stderr)

        replacements = self.build_replacement_table()
        print(f"  Total replacements: {len(replacements)}", file=sys.stderr)

        # Pass 2: Replace ALL files with the shared mapping
        print(f"Pass 2: Writing obfuscated logs...", file=sys.stderr)
        output_paths = []
        for path in input_paths:
            basename = os.path.basename(path)
            if basename.endswith(".log"):
                out_name = basename[:-4] + "_obfuscated.log"
            else:
                out_name = basename + "_obfuscated"
            out_path = os.path.join(output_dir, out_name)
            self._replace_file(path, out_path, replacements)
            output_paths.append(out_path)

        # Write shared mapping
        print(f"Writing mapping to {mapping_path}...", file=sys.stderr)
        with open(mapping_path, "w", encoding="utf-8") as f:
            json.dump(self.registry.get_mapping_report(), f, indent=2,
                      ensure_ascii=False)

        print(f"Complete! {len(input_paths)} file(s) obfuscated.", file=sys.stderr)
        return output_paths


def _resolve_input_paths(inputs):
    """Expand directories and globs into a flat list of log file paths."""
    import glob as globmod
    paths = []
    for entry in inputs:
        if os.path.isdir(entry):
            # Collect all .log files in the directory (non-recursive)
            found = sorted(globmod.glob(os.path.join(entry, "*.log")))
            if not found:
                print(f"  Warning: no .log files found in {entry}",
                      file=sys.stderr)
            paths.extend(found)
        elif "*" in entry or "?" in entry:
            found = sorted(globmod.glob(entry))
            paths.extend(found)
        else:
            paths.append(entry)
    return paths


def main():
    parser = argparse.ArgumentParser(
        description="Obfuscate sensitive data in MongoDB log files "
                    "with consistent replacements across an entire cluster."
    )
    parser.add_argument(
        "input", nargs="+",
        help="One or more log files, directories, or glob patterns. "
             "Directories are scanned for *.log files."
    )
    parser.add_argument(
        "-o", "--output-dir",
        help="Directory for obfuscated output files (default: same dir as "
             "first input file)"
    )
    parser.add_argument(
        "-m", "--mapping",
        help="Path for the shared mapping JSON file "
             "(default: <output-dir>/cluster_mapping.json)"
    )
    args = parser.parse_args()

    input_paths = _resolve_input_paths(args.input)
    if not input_paths:
        print("Error: no input files found.", file=sys.stderr)
        sys.exit(1)

    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.dirname(os.path.abspath(input_paths[0]))

    os.makedirs(output_dir, exist_ok=True)

    # Determine mapping path
    if args.mapping:
        mapping_path = args.mapping
    else:
        mapping_path = os.path.join(output_dir, "cluster_mapping.json")

    print(f"Input files:  {len(input_paths)}", file=sys.stderr)
    for p in input_paths:
        print(f"  {p}", file=sys.stderr)
    print(f"Output dir:   {output_dir}", file=sys.stderr)
    print(f"Mapping file: {mapping_path}", file=sys.stderr)
    print(file=sys.stderr)

    MongoLogObfuscator().process(input_paths, output_dir, mapping_path)


if __name__ == "__main__":
    main()

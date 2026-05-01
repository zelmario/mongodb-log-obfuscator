# MongoDB Obfuscator

A Python tool that strips sensitive data from MongoDB **log files** and **FTDC diagnostic files** while preserving structure and analytical value. Produces obfuscated output safe for sharing with support teams, vendors, or public bug reports, plus a private mapping file to decode values when needed.

Supports **all MongoDB deployment types**: standalone, replica set, and sharded cluster (including mongos, config servers, shard servers, and balancer operations).

## Coherent Obfuscation Across Logs and FTDC

The tool processes **all files at once** — logs and FTDC alike — using a **single shared mapping**, guaranteeing that the obfuscation is **coherent** across every file:

- If `mongo-prod-01.acmecorp.com` appears in the primary's log, a secondary's log, and an FTDC `serverStatus` reference document, it becomes `host1.example.com` **in all of them**.
- If `shard-east-01` is referenced by the balancer on the config server and by the migration coordinator on the shard, it becomes `shard1` **everywhere**.
- The same database name, collection name, replica set name, IP address, username, or any other sensitive value always maps to the **exact same replacement** regardless of which file or file type it appears in.

This means you can still correlate events across nodes, trace replication chains, and follow chunk migrations in the obfuscated output — the relationships between nodes are preserved, only the real names are gone.

**How it works**: Pass 1 scans **all** input files (logs line-by-line, FTDC via BSON decoding and metric chunk decompression) into one shared registry before any replacement happens. Pass 2 applies that single registry to every file. No file is replaced until every file has been scanned.

## Table of Contents

- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Directory Input (Recommended)](#directory-input-recommended)
  - [Custom Output](#custom-output)
  - [Load Existing Mapping](#load-existing-mapping)
  - [Command Reference](#command-reference)
- [Output Files](#output-files)
- [FTDC Support](#ftdc-support)
- [How It Works](#how-it-works)
- [Cross-File Coherence](#cross-file-coherence)
- [What Gets Obfuscated](#what-gets-obfuscated)
- [What Is NOT Obfuscated](#what-is-not-obfuscated)
- [Replacement Templates](#replacement-templates)
- [Recognized Log Attribute Keys](#recognized-log-attribute-keys)
- [Log Format Support](#log-format-support)
- [Architecture](#architecture)
- [Deployment Coverage](#deployment-coverage)
- [BSON Document Handling](#bson-document-handling)
- [Regex Patterns](#regex-patterns)
- [Limitations](#limitations)

---

## Quick Start

```bash
# Point at a support bundle / cluster dump folder — it does the rest
python3 mongodb_obfuscator.py /path/to/logs/

# Custom output directory
python3 mongodb_obfuscator.py /path/to/cluster_dump/ -o /sanitized/
```

The tool recursively scans the input directory for `.log` files and FTDC files (anything inside `diagnostic.data/` directories), obfuscates everything with a shared mapping, and writes the output to an `obfuscated/` subdirectory inside the input, preserving the original directory structure.

### Requirements

- Python 3.6+
- No external dependencies (stdlib only)

---

## Usage

### Directory Input (Recommended)

Point at the root of a support bundle or cluster dump. The tool recursively finds all log and FTDC files:

```bash
python3 mongodb_obfuscator.py /path/to/logs/
```

Input structure:
```
logs/
    mongod-0.log
    diagnostic.data/
        diagnostic.data/
            metrics.2025-12-10T02-44-05Z-00000
            metrics.2025-12-10T08-41-34Z-00000
            metrics.interim
```

Output (inside `obfuscated/` subdirectory, originals untouched):
```
logs/
    mongod-0.log                          <-- original, untouched
    diagnostic.data/                      <-- original, untouched
        ...
    obfuscated/                           <-- all obfuscated output here
        mongod-0_obfuscated.log
        diagnostic.data/
            diagnostic.data/
                metrics.2025-12-10T02-44-05Z-00000
                metrics.2025-12-10T08-41-34Z-00000
                metrics.interim
        cluster_mapping.json
```

You can also pass multiple directories, individual files, or glob patterns:

```bash
# Multiple directories (e.g., multi-node cluster)
python3 mongodb_obfuscator.py /dumps/node1/ /dumps/node2/ /dumps/node3/

# Mix of files and directories
python3 mongodb_obfuscator.py /dumps/shards/ /dumps/config/ /dumps/mongos.log

# Glob patterns
python3 mongodb_obfuscator.py /dumps/node*/mongod.log /dumps/node*/diagnostic.data/
```

### Custom Output

```bash
# Custom output directory
python3 mongodb_obfuscator.py /dumps/cluster/ -o /sanitized/

# Custom mapping file path
python3 mongodb_obfuscator.py /dumps/cluster/ -o /sanitized/ -m /sanitized/my_mapping.json
```

### Load Existing Mapping

Continue a prior obfuscation run or merge with another pass:

```bash
# Load a mapping from a previous run to maintain coherence
python3 mongodb_obfuscator.py /dumps/node4/ --load-mapping /sanitized/cluster_mapping.json -o /sanitized/node4/
```

### Command Reference

```
usage: mongodb_obfuscator.py [-h] [-o OUTPUT_DIR] [-m MAPPING]
                             [--load-mapping LOAD_MAPPING]
                             input [input ...]

Obfuscate sensitive data in MongoDB log files and FTDC diagnostic files with
coherent, consistent replacements across an entire cluster. Recreates the
input directory structure in the output.

positional arguments:
  input                 One or more directories, log files, FTDC files, or
                        glob patterns. Directories are scanned recursively
                        for *.log files and diagnostic.data/ FTDC files.

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Root directory for obfuscated output
                        (default: <input>/obfuscated/)
  -m MAPPING, --mapping MAPPING
                        Path for the shared mapping JSON file
                        (default: <output-dir>/cluster_mapping.json)
  --load-mapping LOAD_MAPPING
                        Load an existing mapping to continue a prior run
                        or merge with another obfuscation pass
```

---

## Output Files

| File | Purpose | Share? |
|------|---------|--------|
| `*_obfuscated.log` | Sanitized log — same format as input, all sensitive values replaced | Safe to share |
| FTDC `metrics.*` | Sanitized FTDC — same binary format, all sensitive strings replaced, all numeric metrics preserved exactly | Safe to share |
| `cluster_mapping.json` | Original-to-replacement lookup for all files, grouped by category | **Keep private** |

---

## FTDC Support

The tool includes a **pure-Python BSON codec** and **FTDC chunk decompressor/recompressor** to handle MongoDB's Full Time Diagnostic Data Capture files with zero external dependencies.

### What happens to FTDC files

FTDC files contain three document types:

| Type | Name | Processing |
|------|------|------------|
| 0 | **Metadata** | Full BSON document (e.g., `serverStatus` output). All sensitive string fields are obfuscated. |
| 1 | **Metric Chunk** | Compressed reference BSON + delta-encoded numeric time series. The reference document's strings are obfuscated; the **numeric delta stream is preserved byte-for-byte**. All metric data is intact. |
| 2 | **Periodic Metadata** | Configuration change deltas. String fields are obfuscated. |

### How metric chunks are processed

1. Decompress the zlib payload
2. Extract the reference BSON document and the delta stream
3. Obfuscate sensitive strings in the reference document
4. Re-compress with the **identical delta stream** — numeric metrics are untouched

This works because FTDC's delta compression only tracks numeric fields. String fields exist solely in the reference document, so modifying strings and keeping the delta stream byte-for-byte is safe.

### FTDC-specific keys

In addition to the 130+ log attribute keys, the tool recognizes FTDC-specific fields:

- `me` — the node's own host:port in `serverStatus` repl section
- `set` — replica set name in `replSetGetStatus`
- `hosts`, `passives`, `arbiters` — BSON arrays of host:port strings in replication sections
- `advisoryHostFQDNs` — array of advisory FQDNs
- `name` in `members[]` arrays — host:port of replica set members

### File detection

Files are automatically classified:

| Pattern | Classification |
|---------|---------------|
| `*.log` | Log file |
| Files inside `diagnostic.data/` directories | FTDC |
| `metrics.*` or `metrics` filename | FTDC |
| `*.ftdc` extension | FTDC |
| Binary content (null bytes in header) | FTDC |
| Archive files (`.tar.gz`, `.zip`, etc.) | Skipped |

---

## How It Works

The obfuscator uses a **two-pass architecture**:

### Pass 1 — Discovery (all files)

Reads **every** input file and builds a single shared mapping of all sensitive values found across the entire cluster:

**For log files:**
1. Each JSON log line is parsed and recursively walked (`deep_discover`)
2. Every attribute key is checked against categorized key sets (host keys, database keys, shard keys, etc.)
3. Values are classified and registered in one shared `ObfuscatorRegistry`
4. Free-text fields (`msg`, `error`, etc.) are scanned with regex for IPs, FQDNs, emails, LDAP DNs, and Java class names
5. Embedded BSON documents in stringified form are parsed for key-value pairs
6. Non-JSON lines (legacy format) are scanned with full regex patterns

**For FTDC files:**
1. Sequential BSON documents are decoded from the binary file
2. Metadata documents have their `doc` field recursively walked (`deep_discover_bson`)
3. Metric chunks are decompressed and the reference BSON document is walked
4. Periodic metadata documents have their `doc` field walked
5. BSON arrays (e.g., `hosts: ["node1:27017", "node2:27017"]`) are handled natively

### Pass 2 — Replacement (all files)

Re-reads **every** file and performs replacement using the shared mapping:

**For log files:**
1. All replacements are sorted longest-first to prevent partial matches
2. Each line is scanned for every known original value and replaced
3. Output is written to `*_obfuscated.log`

**For FTDC files:**
1. Each BSON document is decoded, string values are replaced, and the document is re-encoded
2. Metric chunks are decompressed, the reference document is obfuscated, and the chunk is re-compressed with the identical delta stream
3. Output files keep their original names

---

## Cross-File Coherence

When processing multiple files, the tool guarantees **consistent replacements across all files** — both logs and FTDC. This is critical for cluster diagnostics where the same hostname, shard name, or replica set name appears in logs from different nodes and in FTDC diagnostic data.

The mechanism is simple: Pass 1 scans **all** files into **one** `ObfuscatorRegistry` before any replacement happens. Then Pass 2 applies that single registry to every file.

For example, given a 3-node replica set + 1 mongos:

| Original value | Replacement | node1.log | node2.log | node1 FTDC | mongos.log |
|---|---|---|---|---|---|
| `mongo-pay-01.fintech.internal` | `host1.example.com` | `host1.example.com` | `host1.example.com` | `host1.example.com` | `host1.example.com` |
| `rs-payments` | `replset1` | `replset1` | - | `replset1` | `replset1` |
| `shard-payments` | `shard1` | - | - | - | `shard1` |
| `payments_prod` | `database1` | `database1` | `database1` | - | - |

The same original value always produces the same replacement, regardless of which file or file type it appears in.

---

## What Gets Obfuscated

### 17 Obfuscation Categories

| # | Category | Example Original | Example Replacement | Description |
|---|----------|-----------------|---------------------|-------------|
| 1 | **hostname** | `mongo-prod-01` | `host1` | Short hostnames (no dots) |
| 2 | **fqdn** | `mongo-prod-01.acmecorp.com` | `host1.example.com` | Fully qualified domain names |
| 3 | **domain** | `acmecorp.com` | `domain1.example.com` | Domain portions extracted from FQDNs/emails |
| 4 | **ip** | `192.168.1.100` | `10.0.0.1` | IPv4 addresses (except localhost/0.0.0.0) |
| 5 | **database** | `myapp_production` | `database1` | Database names (except `admin`, `local`, `config`) |
| 6 | **collection** | `user_profiles` | `collection1` | Collection names (except `system.*` and `$*`) |
| 7 | **replset** | `rs-prod-east` | `replset1` | Replica set names |
| 8 | **shard** | `shard-prod-east-01` | `shard1` | Shard names and shard IDs |
| 9 | **user** | `admin_prod` | `user1` | Usernames (non-email format) |
| 10 | **email** | `john@acmecorp.com` | `user1@example.com` | Email addresses |
| 11 | **path** | `/data/db/mongo-prod-01` | `/obfuscated/path1` | File system paths |
| 12 | **cert_subject** | `CN=server.acmecorp.com,O=AcmeCorp,C=US` | `CN=cert1.example.com,O=Organization,...` | TLS/SSL certificate subject strings |
| 13 | **org** | `AcmeCorp Inc` | `Organization1` | Organization names from certs/LDAP |
| 14 | **location** | `San Francisco` | `Location1` | Location names from certs (L=, ST=) |
| 15 | **java_class** | `com.mongodb.client.MongoClient` | `com.example.app.Class1` | Java class names (driver stack traces) |
| 16 | **appname** | `PaymentService` | `app1` | Application names from client metadata |
| 17 | **data** | `ACME Corp` | `data_1` | Generic catch-all for business data in BSON documents |

---

## What Is NOT Obfuscated

These values are intentionally preserved because they are operational metadata, not PII:

| Category | Examples | Reason |
|----------|----------|--------|
| **Internal databases** | `admin`, `local`, `config` | MongoDB system databases |
| **System collections** | `system.sessions`, `system.profile` | MongoDB internal collections |
| **Log envelope fields** | `t`, `s`, `c`, `id`, `ctx`, `svc` | Structural log metadata |
| **Numeric metrics** | `durationMillis`, `docsExamined`, `keysExamined` | Performance data |
| **FTDC numeric time series** | All delta-compressed metrics | Preserved byte-for-byte |
| **Version strings** | `gitVersion`, `openSSLVersion` | Software versions |
| **Numbers** | `42`, `3.14`, `-1` | Pure numeric values |
| **Hex strings** | `507f1f77bcf86cd799439011` | ObjectIds, hashes (24+ hex chars) |
| **UUIDs** | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` | Opaque identifiers |
| **BSON type markers** | `ObjectId(...)`, `Date(...)`, `Timestamp(...)` | Type wrappers |
| **Booleans/status** | `true`, `false`, `ACTIVE`, `COMPLETED` | Operational status values |
| **Read/write concerns** | `majority`, `linearizable`, `snapshot` | Consistency levels |
| **Country/currency codes** | `US`, `USD`, `EUR` | ISO standard codes |
| **MongoDB operators** | `$set`, `$match`, `$group` | Query/update operators |
| **Port numbers** | `27017`, `27018` | Kept in SKIP_KEYS |

---

## Replacement Templates

Each category uses a deterministic template that increments per unique value:

| Category | Template | Sequence |
|----------|----------|----------|
| hostname | `host{n}` | host1, host2, host3... |
| fqdn | `host{n}.example.com` | host1.example.com, host2.example.com... |
| domain | `domain{n}.example.com` | domain1.example.com, domain2.example.com... |
| ip | `10.{(n>>16)&0xFF}.{(n>>8)&0xFF}.{n&0xFF}` | 10.0.0.1, 10.0.0.2... |
| database | `database{n}` | database1, database2... |
| collection | `collection{n}` | collection1, collection2... |
| replset | `replset{n}` | replset1, replset2... |
| shard | `shard{n}` | shard1, shard2... |
| user | `user{n}` | user1, user2... |
| email | `user{n}@example.com` | user1@example.com, user2@example.com... |
| path | `/obfuscated/path{n}` | /obfuscated/path1, /obfuscated/path2... |
| cert_subject | `CN=cert{n}.example.com,O=Organization,L=City,ST=State,C=XX` | Full DN template |
| org | `Organization{n}` | Organization1, Organization2... |
| location | `Location{n}` | Location1, Location2... |
| java_class | `com.example.app.Class{n}` | com.example.app.Class1... |
| appname | `app{n}` | app1, app2... |
| data | `data_{n}` | data_1, data_2... |

---

## Recognized Log Attribute Keys

The obfuscator recognizes **130+** MongoDB LOGV2 attribute keys, derived from analysis of all 2,233 unique attribute keys in the Percona Server for MongoDB 8.0 source code (`"keyName"_attr` patterns in `src/mongo/`).

### Hosts & Network (HOST_KEYS)

Attribute keys whose values contain hostname, host:port, or IP address data:

```
host, hostAndPort, hostName, me,
syncSource, syncSourceHost, syncSourceCandidate,
candidateNode, candidate, peer,
newSyncSource, oldSyncSource, previousSyncSource,
currentSyncSource, unsupportedSyncSource, syncTarget,
eligibleCandidateSyncSource,
remoteHost, senderHost, donorHost,
addr, address, addressString,
server, serverAddress, serverHost,
endpoint, localEndpoint,
primary, newPrimary, targetPrimary,
closestNode, selectedNode, node, otherMember,
requestTarget, request_target, request_target_host,
target, cursorHost,
failedHost, sniName
```

### Remote/Local Connections (REMOTE_LOCAL_KEYS)

```
remote, local, remoteAddr, remoteSocketAddress,
remoteString, remoteAddress, sourceClient
```

### Client (CLIENT_KEYS)

```
client
```

Values matching `conn\d+` (connection IDs) are skipped.

### Namespaces (NAMESPACE_KEYS)

Attribute keys whose values contain `database.collection` namespace strings:

```
ns, namespace, nss,
sourceNss, targetNss, newNss, oldNss,
sourceNamespace, targetNamespace, destinationNamespace,
originalCollection, outputNamespace, resolvedNs,
fromNs, toNs,
oplogNamespace, oplogNss,
ecocNss, ecocCompactNss, ecocRenameNss,
reshardingTmpNss, lostAndFoundNss,
existingTargetNamespace, newTargetNamespace,
configSettingsNamespace, affectedNamespaces,
dbNss, docNss
```

### Databases (DATABASE_KEYS)

```
database, db, dbName, dbname
```

Internal databases (`admin`, `local`, `config`, `$external`) are never obfuscated.

### Collections (COLLECTION_KEYS)

```
collection, coll, collName,
tempCollection, temporaryCollection, newCollection,
sourceCollection, defragmentCollection
```

System collections (`system.*`, `$*`) are never obfuscated.

### Replica Set Names (REPLSET_KEYS)

```
replSetName, setName, configServerSetName,
replicaSet, set,
newConfigSetName, oldConfigSetName, localConfigSetName,
commandLineSetName, ourSetName, initiateSetName,
remoteNodeSetName
```

### Shard Names/IDs (SHARD_KEYS)

```
shard, shardId,
fromShard, fromShardId, toShard, toShardId,
donorShard, donorShardId,
recipientShard, recipientShardId, recipientId,
coordinatorShardId, writeShardId,
dataShard, mergingShardId,
firstShardId, secondShardId
```

### Users (USER_KEYS)

```
user, userName, queryUser
```

Values containing `@` are treated as emails; others as usernames.

### File Paths (PATH_KEYS)

```
dbPath, dbpath, path, filePath, filepath,
localFilePath, remoteFilePath,
keyfile, cafile, crlFile, CRLFile,
configPath, logPath, newLogPath, oldLogPath,
file, fileName, filename,
dir, directory, dataDirectory,
destFile, srcFile, localFile, remoteFile,
lockFile, jsonConfigPath, remoteDBPath,
_pipeAbsolutePath
```

### Certificate Subjects (CERT_SUBJECT_KEYS)

```
peerSubject, peerSubjectName, subjectName,
subject, issuer, dn
```

Certificate DN strings are parsed to also extract Organization (O=, OU=), Location (L=, ST=), and CN hostnames.

### Connection Strings (CONN_STRING_KEYS)

```
targetClusterConnectionString, connString, connectionString,
replicaSetConnectionStr, shardConnectionString,
newConnString, oldConnString, currentConnString,
newConnectionString, givenConnString,
uri, mongoUri, ldapurl
```

Connection strings are parsed to extract hosts, database names, and `replicaSet=` query parameters. Non-MongoDB URIs (ldap://, etc.) are also parsed for host extraction.

### Application Names (APP_NAME_KEYS)

```
appName, clientName
```

### Free-Text Fields (FREETEXT_KEYS)

```
msg, error, errmsg, reason, message, info,
errorMessage, errorMsg, err_msg, description, desc
```

These are scanned with regex patterns for embedded IPs, FQDNs, emails, LDAP DN components, Java class names, and BSON key-value pairs.

### Host Lists (HOST_LIST_KEYS)

```
addresses, failedHosts, nodes, configServers,
listenAddrs, attemptedHosts,
hosts, passives, arbiters, advisoryHostFQDNs
```

Values are split on commas (log files) or iterated as BSON arrays (FTDC files), and each part is processed as a host.

### Skip Keys (SKIP_KEYS)

Keys that are **never processed** (structural/numeric metadata):

```
t, s, c, id, ctx, svc, tags,
connectionId, connectionCount, durationMillis, millis,
workingMillis, timeAcquiringMicros, numYields, nreturned,
docsExamined, keysExamined, nscanned, cpuNanos, durationMicros, latency,
txnNumber, clientTxnNumber, opId,
version, gitVersion, openSSLVersion, minWireVersion, maxWireVersion,
port, votes, priority, term,
ok, code, codeName, result,
featureCompatibilityVersion,
numMembers, numShards, numChunks, numDocs,
bytesCloned, docsCloned, keysInserted, numRecords, numIndexes
```

### Fallback for Unrecognized Keys

Any key not listed above and not in SKIP_KEYS triggers a **light freetext scan** -- if the value contains an IP address, email, or FQDN pattern, a full freetext scan is performed. This catches sensitive data in keys that may be added in future MongoDB versions.

---

## Log Format Support

### Structured JSON Logs (MongoDB 4.4+)

Primary format. Each line is parsed as JSON:

```json
{
  "t": {"$date": "2024-01-15T10:30:45.123Z"},
  "s": "I",
  "c": "REPL",
  "id": 21392,
  "ctx": "replCoord",
  "msg": "New replica set config in use",
  "attr": {
    "config": {
      "members": [
        {"_id": 0, "host": "mongo-prod-01.acme.com:27017"}
      ]
    }
  }
}
```

The `attr` object is recursively walked. Nested objects and arrays at any depth (up to 20) are processed. Special handling exists for:
- `members` arrays (replica set member host extraction)
- `options` objects (startup configuration: net, replication, storage, security, LDAP)
- `command`/`cmdObj`/`originatingCommand` objects (collection name extraction from MongoDB commands including `find`, `aggregate`, `insert`, `update`, `delete`, `findAndModify`, `count`, `distinct`, `getMore`, `create`, `drop`, `renameCollection`, `createIndexes`, `dropIndexes`, `collMod`)

### Legacy Text Logs (pre-4.4)

Lines that fail JSON parsing are scanned with full regex patterns:

```
2024-01-15T10:30:45.123+00:00 I NETWORK [listener] connection from 192.168.1.100:45678
```

IPs, FQDNs, emails, LDAP DNs, and Java class names are extracted via regex.

---

## Architecture

### Multi-file processing flow

```
  node1/              node2/              mongos/
  mongod.log          mongod.log          mongos.log
  diagnostic.data/    diagnostic.data/    diagnostic.data/
      metrics.*           metrics.*           metrics.*
      │                   │                   │
      └───────────────────┴─────┬─────────────┘
                                │
                         PASS 1: Discovery
                    (scan ALL files into ONE registry)
                                │
               ┌────────────────▼────────────────┐
               │       ObfuscatorRegistry        │
               │           (shared)              │
               │                                 │
               │  hostname:  {orig: repl}        │
               │  fqdn:      {orig: repl}        │
               │  ip:        {orig: repl}        │
               │  shard:     {orig: repl}        │
               │  replset:   {orig: repl}        │
               │  ...17 categories total         │
               └────────────────┬────────────────┘
                                │
                         PASS 2: Replace
                    (apply shared registry to ALL)
                                │
      ┌─────────────────────────┼─────────────────────────┐
      │                         │                         │
      ▼                         ▼                         ▼
  obfuscated/               obfuscated/               obfuscated/
  node1/                    node2/                    mongos/
  mongod_obfuscated.log     mongod_obfuscated.log     mongos_obfuscated.log
  diagnostic.data/          diagnostic.data/          diagnostic.data/
      metrics.*                 metrics.*                 metrics.*

                      + cluster_mapping.json
```

### Per-file discovery flow (log files)

```
           ┌────────────────────────┐
           │    json.loads(line)    │──── fail ──→ _discover_freetext()
           └────────────┬───────────┘              (regex scan)
                        │ success
                        ▼
           ┌─────────────────────────┐
           │    deep_discover(obj)   │ ◄── recursive walk, depth <= 20
           │                         │
           │  For each key, val:     │
           │    ├─ REPLSET_KEYS?     │──→ register("replset", val)
           │    ├─ SHARD_KEYS?       │──→ register("shard", val)
           │    ├─ DATABASE_KEYS?    │──→ register("database", val)
           │    ├─ COLLECTION_KEYS?  │──→ register("collection", val)
           │    ├─ NAMESPACE_KEYS?   │──→ parse db.collection
           │    ├─ USER_KEYS?        │──→ register("user"/"email", val)
           │    ├─ CERT_SUBJECT_KEYS?│──→ parse DN components
           │    ├─ PATH_KEYS?        │──→ register("path", val)
           │    ├─ HOST_KEYS?        │──→ parse host:port -> hostname/fqdn/ip
           │    ├─ REMOTE_LOCAL_KEYS?│──→ parse host:port
           │    ├─ CLIENT_KEYS?      │──→ parse host (skip conn\d+)
           │    ├─ CONN_STRING_KEYS? │──→ parse mongodb:// URI
           │    ├─ APP_NAME_KEYS?    │──→ register("appname", val)
           │    ├─ HOST_LIST_KEYS?   │──→ split comma, parse each host
           │    ├─ FREETEXT_KEYS?    │──→ regex scan + BSON scan
           │    ├─ SKIP_KEYS?        │──→ (skip entirely)
           │    └─ (other)?          │──→ _discover_freetext_light(val)
           └─────────────────────────┘
```

### Per-file discovery flow (FTDC files)

```
           ┌─────────────────────────────┐
           │  decode BSON documents       │
           │  from binary file            │
           └────────────┬────────────────┘
                        │
           ┌────────────▼────────────────┐
           │  For each FTDC document:    │
           │    ├─ type 0 (metadata)?    │──→ deep_discover_bson(doc)
           │    ├─ type 1 (metric)?      │──→ decompress chunk
           │    │                        │    extract reference BSON
           │    │                        │    deep_discover_bson(ref_doc)
           │    └─ type 2 (periodic)?    │──→ deep_discover_bson(doc)
           └─────────────────────────────┘
```

---

## Deployment Coverage

Coverage is based on analysis of all 2,233 LOGV2 attribute keys in the Percona Server for MongoDB 8.0 source code.

| Deployment Type | Log Coverage | FTDC Coverage | Notes |
|----------------|-------------|---------------|-------|
| **Standalone** | ~98% | ~98% | Covers connections, auth, commands, paths, TLS, LDAP |
| **Replica Set** | ~98% | ~98% | Covers member hosts, sync sources, elections, heartbeats, configs |
| **Sharded Cluster** | ~98% | ~98% | Covers shard IDs, chunk migrations, resharding, balancer, config servers, mongos routing |
| **Legacy text logs** | ~90% | N/A | Regex-based -- catches IPs, FQDNs, emails; may miss short hostnames in unstructured text |

---

## BSON Document Handling

Embedded BSON documents within free-text fields (like oplog entries in error messages) are parsed generically without hardcoded field names:

1. All `key: "value"` pairs are extracted via regex
2. Values are classified by content pattern (namespace, host, shard, email, IP, path, FQDN, Java class)
3. Values matching safety checks are skipped:
   - Structural BSON keys (`op`, `ts`, `$set`, `filter`, etc.)
   - Known safe values (`true`, `false`, `majority`, status enums, etc.)
   - Country codes (ISO 3166-1 alpha-2)
   - Currency codes (ISO 4217)
   - Pure numbers, hex strings (ObjectIds), UUIDs
   - Single characters, BSON type markers
4. Everything else is registered as generic `data`

---

## Regex Patterns

| Pattern | Purpose | Regex |
|---------|---------|-------|
| `RE_IP` | IPv4 addresses | `\b(?:\d{1,3}\.){3}\d{1,3}\b` |
| `RE_FQDN` | Fully qualified domain names | `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}\b` |
| `RE_EMAIL` | Email addresses | `\b[\w.+-]+@[\w.-]+\.\w{2,}\b` |
| `RE_LDAP_DN_COMPONENT` | LDAP DN parts (DC=, OU=, CN=, O=, L=, ST=) | `\b(?:DC\|OU\|CN\|O\|L\|ST)=([A-Za-z][A-Za-z0-9 ._-]*)` |
| `RE_JAVA_CLASS` | Java class names | `\b((?:[a-z][a-z0-9]*\.){2,}[A-Z]\w*)\b` |
| `RE_BSON_STRING_FIELD` | Key-value pairs in stringified BSON | `(\w+):\s*"([^"]*)"` |
| `RE_PURE_NUMBER` | Numbers (safe, not obfuscated) | `^-?\d+\.?\d*$` |
| `RE_HEX` | Hex strings, ObjectIds (safe) | `^[0-9a-fA-F]{24,}$` |
| `RE_UUID_LIKE` | UUID format (safe) | `^[0-9a-fA-F]{8}-...-[0-9a-fA-F]{12}$` |

---

## Limitations

1. **Two-pass requirement**: All input files must be read twice -- once for discovery, once for replacement. The tool cannot stream logs in real-time.

2. **Memory**: All unique sensitive values and their mappings are held in memory. For very large log sets with millions of unique values, memory usage could be significant.

3. **String replacement**: Replacement is done via simple `str.replace()`, not JSON-aware. In rare cases, a short sensitive value could match a substring in an unrelated context. Longest-first ordering mitigates this.

4. **Depth limit**: Nested JSON/BSON structures are walked to a maximum depth of 20. Extremely deep nesting beyond this limit will not be processed.

5. **FQDN heuristics**: The FQDN regex filters out entries starting with digits, containing uppercase characters, having more than 4 parts, or matching known non-domains. Some edge-case FQDNs may be missed.

6. **Short hostnames in unknown keys**: For attribute keys not in any recognized set, the fallback light scan only triggers full freetext analysis if an IP, email, or FQDN pattern is detected. A bare short hostname (e.g., `"mykey": "prodserver"`) in an unrecognized key will not be caught.

7. **Connection string passwords**: If a MongoDB connection string contains embedded credentials (`mongodb://user:password@host/db`), the password portion is not explicitly handled. The host and database portions are obfuscated, but password handling should rely on MongoDB's own log redaction (`--redactClientLogData`).

8. **FTDC schema preservation**: When obfuscating FTDC metric chunks, the reference document's field structure (names, types, order) must not change — only string values are modified. This is guaranteed by the current implementation, but adding/removing fields would break the delta stream alignment.

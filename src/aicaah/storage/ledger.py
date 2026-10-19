# -*- coding: utf-8 -*-
"""편집 이력과 경고 장부(SPEC-36 2.10). 패스마다 장부의 색인 대비 변경을 이력에 쌓고, 지적을 열쇠로 대조해
새 지적·해소를 가린다. 한 번 알린 지적은 장부에 남아 다시 새 지적이 되지 않는다. 받는 쪽마다 마지막으로 받은 판을 둔다."""
import atexit
import contextlib
import datetime
import json
import marshal
import os
import sqlite3
import threading
import time
import uuid
import zlib

from storage import diff as diffmod
from storage import relations
from parsing import cache as cachemod

if os.name == "nt":
    import msvcrt
else:
    import fcntl

HISTORY_ROOT = ".spec-conformance/History"
LEDGER_FILE = HISTORY_ROOT + "/ledger-state/state.row"
STATE_ROOT = HISTORY_ROOT + "/ledger-state"
_STATE_READY = set()
_STATUS_ROWS = {}
CHANGES_FILE = HISTORY_ROOT + "/changes.jsonl"
LOCK_FILE = HISTORY_ROOT + "/ledger.lock"
LOCK_SECONDS = 600.0
FILE_ROWS = HISTORY_ROOT + "/ledger-files"
_FILE_ROWS = {}


class SourceIndex(dict):
    """Scalar file headers with on-demand, file-owned declaration rows."""

    def __init__(self, root, rows, headers=None):
        self.root, self.rows, self.loaded, self.changed = root, dict(rows), set(), set()
        self.versions = {}
        if headers is None and not rows:
            headers = {}
        if headers is None:
            connection = table_connection(root, FILE_ROWS + "/index.row")
            columns = [key for key, _ in relations.SOURCE_ENTRY.columns]
            query = "SELECT r.file,r.input," + ",".join('s."'+key+'"' for key in columns) + ",s.fields FROM records r JOIN source_entries s ON s.record_file=r.file"
            wanted = {table_location(root, rel)[1]: file for file, rel in rows.items()}
            headers = {}
            for record, version, *values in connection.execute(query):
                if record in wanted:
                    self.versions[wanted[record]] = version
                    mask = values.pop()
                    headers[wanted[record]] = {key:value for i,(key,value) in enumerate(zip(columns,values)) if mask & (1 << i)}
            if headers.keys() != rows.keys():
                raise ValueError("missing source index headers")
        super().__init__(headers)

    def __getitem__(self, file):
        if file not in self.loaded:
            row = read_table(self.root, self.rows[file], None)
            if row is None:
                raise ValueError("missing ledger file row: " + file)
            dict.__setitem__(self, file, row["entry"])
            self.loaded.add(file)
        return dict.__getitem__(self, file)

    def get(self, file, default=None):
        return self[file] if file in self else default

    def __setitem__(self, file, entry):
        dict.__setitem__(self,file,entry)
        self.loaded.add(file)
        self.changed.add(file)

    def __delitem__(self, file):
        dict.__delitem__(self,file)
        self.loaded.discard(file)
        self.changed.add(file)

    def items(self):
        return ((file,self[file]) for file in self)

    def values(self):
        return (self[file] for file in self)

    def summaries(self):
        return dict.items(self)

    def copy(self):
        result = SourceIndex(self.root,self.rows,dict(dict.items(self)))
        result.loaded = set(self.loaded)
        result.versions = dict(self.versions)
        return result

    def fingerprint(self, file):
        """검증된 원천 게시 키만 읽어 무변경 파일의 선언 행 적재를 피한다."""
        if file not in self:
            return None
        if file not in self.changed and self.versions.get(file) == cachemod.POLICY.versions['publication-source']:
            return self.rows[file].rsplit('.',2)[-2]
        return cachemod.POLICY.key('publication-source',self[file])


def write_json(root, rel, value):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def read_binary(root, rel, default):
    """기본 자료형 이력 레코드를 읽는다. 없는 파일만 기본값, 손상은 호출자에게 전달한다."""
    try:
        with open(os.path.join(root,rel),"rb") as stream:
            return marshal.load(stream)
    except FileNotFoundError:
        return default


def write_binary(root, rel, value):
    """기본 자료형 레코드를 바이너리로 원자 교체한다. 실패 시 기존 레코드를 보존한다."""
    path = os.path.join(root,rel)
    os.makedirs(os.path.dirname(path),exist_ok=True)
    temporary = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        payload = marshal.dumps(value)
        with open(temporary,"wb") as stream:
            stream.write(payload)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


_TABLE_CONNECTIONS = {}
_TABLE_CONNECTION_LIMIT = 64
_TABLE_CACHE_KIB = 8192
_TABLE_STATEMENTS = 128
_TABLE_LIVE = {}
_TABLE_LOCK = threading.RLock()
_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS records(file TEXT PRIMARY KEY, source TEXT NOT NULL UNIQUE, input TEXT,
 has_input INTEGER NOT NULL, relations TEXT NOT NULL, has_lookup INTEGER NOT NULL, has_checks INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS symbols(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS names(file TEXT NOT NULL REFERENCES records(file) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, symbol INTEGER NOT NULL REFERENCES symbols(id), PRIMARY KEY(file,ordinal));
CREATE INDEX IF NOT EXISTS name_symbol ON names(symbol);
CREATE TABLE IF NOT EXISTS edges(file TEXT NOT NULL REFERENCES records(file) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, source INTEGER NOT NULL REFERENCES symbols(id), target INTEGER NOT NULL REFERENCES symbols(id),
 line INTEGER, writing INTEGER, guess INTEGER, PRIMARY KEY(file,ordinal));
CREATE INDEX IF NOT EXISTS edge_target ON edges(target,file);
CREATE INDEX IF NOT EXISTS edge_source ON edges(source,file);
CREATE TABLE IF NOT EXISTS queries(file TEXT NOT NULL REFERENCES records(file) ON DELETE CASCADE,
 query TEXT NOT NULL, shape TEXT NOT NULL, PRIMARY KEY(file,query));
CREATE INDEX IF NOT EXISTS query_users ON queries(query,file);
CREATE TABLE IF NOT EXISTS query_candidates(file TEXT NOT NULL, query TEXT NOT NULL, ordinal INTEGER NOT NULL,
 lookup_name TEXT, target TEXT NOT NULL, PRIMARY KEY(file,query,ordinal),
 FOREIGN KEY(file,query) REFERENCES queries(file,query) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS candidate_target ON query_candidates(target,file);
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY, file TEXT NOT NULL REFERENCES records(file) ON DELETE CASCADE,
 kind TEXT NOT NULL, slot TEXT NOT NULL, input TEXT, suppressed INTEGER NOT NULL, UNIQUE(file,kind,slot));
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, code TEXT NOT NULL, file TEXT NOT NULL,
 line INTEGER NOT NULL, message TEXT NOT NULL, rule TEXT NOT NULL, UNIQUE(code,file,line,message,rule));
CREATE TABLE IF NOT EXISTS check_findings(check_id INTEGER NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
 finding_id INTEGER NOT NULL REFERENCES findings(id), ordinal INTEGER NOT NULL, PRIMARY KEY(check_id,ordinal));
CREATE INDEX IF NOT EXISTS finding_checks ON check_findings(finding_id,check_id);
CREATE TABLE IF NOT EXISTS ledger_sources(file TEXT PRIMARY KEY, row_rel TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ledger_status(kind TEXT NOT NULL, key TEXT NOT NULL, owner TEXT NOT NULL,
 revision INTEGER NOT NULL, time TEXT, PRIMARY KEY(kind,key));
CREATE INDEX IF NOT EXISTS ledger_status_owner ON ledger_status(owner,kind);
"""
_CHANGE_SQL = """
CREATE TABLE IF NOT EXISTS change_revisions(revision INTEGER PRIMARY KEY, changed_at TEXT NOT NULL,
 trigger TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS code_change_events(revision INTEGER NOT NULL REFERENCES change_revisions(revision),
 ordinal INTEGER NOT NULL, file TEXT NOT NULL, path TEXT NOT NULL, kind TEXT NOT NULL,
 symbol_kind TEXT NOT NULL, name TEXT NOT NULL, signature TEXT NOT NULL, line INTEGER NOT NULL,
 detail TEXT NOT NULL, base_file TEXT NOT NULL, PRIMARY KEY(revision,ordinal));
CREATE INDEX IF NOT EXISTS code_change_file ON code_change_events(file,revision);
CREATE TABLE IF NOT EXISTS document_change_events(revision INTEGER NOT NULL REFERENCES change_revisions(revision),
 ordinal INTEGER NOT NULL, path TEXT NOT NULL, PRIMARY KEY(revision,ordinal));
CREATE INDEX IF NOT EXISTS document_change_path ON document_change_events(path,revision);
"""


def _initialize(connection, change_history=False):
    """Create the current schema. Retired analysis databases must be rebuilt explicitly."""
    version=connection.execute("PRAGMA user_version").fetchone()[0]
    if version in (4, 5):
        # Add only the new owned relations; preserve all current records and masks.
        with connection:
            for model in (relations.PRODUCER_VERSIONS, relations.SERVER_SETTINGS):
                for sql in relations.schema(model, relations.ROOT.name):
                    connection.execute(sql)
    if version==5 or (version==4 and not change_history): return
    if version==4 and change_history:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            for sql in _CHANGE_SQL.split(';'):
                if sql.strip(): connection.execute(sql)
            connection.execute("PRAGMA user_version=5")
        return
    if version or connection.execute("SELECT 1 FROM sqlite_master WHERE type='table'").fetchone():
        raise ValueError("Retired SQL analysis schema: rebuild derived data from current documents and code")
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        for sql in (_TABLE_SQL + (_CHANGE_SQL if change_history else "")).split(';'):
            if sql.strip(): connection.execute(sql)
        relations.prepare(connection)
        connection.execute("PRAGMA user_version=%d" % (5 if change_history else 4))


def table_location(root, rel):
    """Return a domain database directory and a relative file key, retaining folder identity."""
    normalized = rel.replace("\\","/")
    prefixes = (FILE_ROWS,STATE_ROOT,".spec-conformance/Cache")
    prefix = next((base for base in prefixes if normalized.startswith(base+"/")),None)
    if prefix is None: raise ValueError("table connection outside owned cache")
    rest = normalized[len(prefix)+1:]
    if prefix.endswith("/Cache") and "/" in rest:
        area,rest = rest.split("/",1)
        prefix += "/"+area
    base = os.path.abspath(os.path.join(root,prefix))
    target = os.path.abspath(os.path.join(base,rest))
    if os.path.commonpath((base,target)) != base: raise ValueError("table path escapes its domain")
    return base,rest


def table_connection(root, rel, create=False):
    """One connection per storage domain; source folders are indexed row keys."""
    base,_ = table_location(root,rel)
    path = os.path.join(base,"metadata.sqlite")
    cached = _TABLE_CONNECTIONS.get(path)
    if cached is not None:
        # Reinsert as most recently used; caller holds _TABLE_LOCK through fetching.
        _TABLE_CONNECTIONS.pop(path)
        _TABLE_CONNECTIONS[path] = cached
        return cached
    exists = os.path.isfile(path)
    if not create and not exists and not os.path.isdir(base):
        return None
    if not exists:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    # Connections carry SQLite page/statement/schema caches. Bound the process-wide
    # resident set without discarding any persisted records or an active transaction.
    while len(_TABLE_CONNECTIONS) >= _TABLE_CONNECTION_LIMIT:
        victim = next((key for key, value in _TABLE_CONNECTIONS.items() if not value.in_transaction), None)
        if victim is None:
            break
        _TABLE_CONNECTIONS.pop(victim).close()
    connection = sqlite3.connect(path, timeout=10, check_same_thread=False, cached_statements=_TABLE_STATEMENTS)
    try:
        connection.execute("PRAGMA cache_size=-%d" % _TABLE_CACHE_KIB)
        connection.execute("PRAGMA mmap_size=0")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=NORMAL")
        if not exists:
            connection.execute("PRAGMA journal_mode=WAL")
        _initialize(connection, base == os.path.abspath(os.path.join(root, STATE_ROOT)))
    except BaseException:
        connection.close()
        raise
    _TABLE_CONNECTIONS[path] = connection
    return connection



def table_status():
    """이미 열린 연결 수와 상주 한도만 반환한다. DB 생성·조회·전체 순회는 하지 않는다."""
    return {"residentConnections": len(_TABLE_CONNECTIONS),
            "connectionLimit": _TABLE_CONNECTION_LIMIT,
            "pageCacheKiBPerConnection": _TABLE_CACHE_KIB,
            "statementLimitPerConnection": _TABLE_STATEMENTS}


def query_table(root, rel, sql, parameters=()):
    """소유 폴더 DB의 인덱스 SELECT만 실행한다. 테이블 생성·전체 레코드 복원은 하지 않는다."""
    if not sql.lstrip().upper().startswith('SELECT '): raise ValueError('read-only SELECT required')
    with _TABLE_LOCK:
        connection = table_connection(root, rel)
        return [] if connection is None else connection.execute(sql, parameters).fetchall()


def remove_sources(root, folder, files):
    """Delete only selected source owners; related rows cascade in the same savepoint."""
    if not files:
        return
    with _TABLE_LOCK:
        connection = table_connection(root, folder + "/index.row")
        if connection is None:
            return
        connection.execute("SAVEPOINT remove_sources")
        try:
            connection.executemany("DELETE FROM records WHERE source=?", ((file,) for file in files))
            connection.execute("RELEASE remove_sources")
        except BaseException:
            connection.execute("ROLLBACK TO remove_sources")
            connection.execute("RELEASE remove_sources")
            raise


def _write_rows(connection, file, value):
    """Write declared columns, candidate relationships and per-check finding links."""
    details = dict(value)
    source = details.pop("file")
    inp = details.pop("input", None)
    outgoing = details.pop("outgoing", None)
    edges = details.pop("edges", None)
    lookup = details.pop("lookup", None)
    checks = details.pop("kinds", None)
    if "watch" in details:
        details["watch"] = [dict(cells=row) for row in details["watch"]]
    relation = "outgoing" if outgoing is not None else "edges" if edges is not None else ""
    if outgoing is not None:
        names = outgoing["names"]
        rows = [(names[a], names[b], line, write, guess) for a,b,line,write,guess in outgoing["edges"]]
    else:
        rows = edges or ()
        names = list(dict.fromkeys(key for row in rows for key in row[:2]))
    old_symbols = tuple(connection.execute("SELECT symbol FROM names WHERE file=?",(file,)))
    old_findings = tuple(connection.execute("SELECT cf.finding_id FROM check_findings cf JOIN checks c ON c.id=cf.check_id WHERE c.file=?",(file,)))
    connection.execute("DELETE FROM records WHERE file=?", (file,))
    connection.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?)",
                       (file,source,inp,int("input" in value),relation,int(lookup is not None),int(checks is not None)))
    relations.insert(connection,file,relations.ROOT,[(None,details)])
    connection.executemany("INSERT OR IGNORE INTO symbols(name) VALUES(?)", ((name,) for name in names))
    ids = {}
    for start in range(0,len(names),400):
        batch = names[start:start+400]
        ids.update((name,id) for id,name in connection.execute("SELECT id,name FROM symbols WHERE name IN (%s)" % ",".join("?" for _ in batch),batch))
    connection.executemany("INSERT INTO names VALUES(?,?,?)", ((file,i,ids[name]) for i,name in enumerate(names)))
    connection.executemany("INSERT INTO edges VALUES(?,?,?,?,?,?,?)", ((file,i,ids[a],ids[b],line,int(write),int(guess)) for i,(a,b,line,write,guess) in enumerate(rows)))
    if lookup is not None:
        for query, candidates in lookup.items():
            if isinstance(candidates, str):
                shape, candidates = "scalar", [(None,candidates)]
            elif all(isinstance(item,str) for item in candidates):
                shape, candidates = "symbols", [(None,item) for item in candidates]
            else:
                shape = "members"
                if not all(isinstance(item,(tuple,list)) and len(item)==2 and all(isinstance(x,str) for x in item) for item in candidates):
                    raise ValueError("invalid query candidates: " + query)
            connection.execute("INSERT INTO queries VALUES(?,?,?)",(file,query,shape))
            connection.executemany("INSERT INTO query_candidates VALUES(?,?,?,?,?)",
                                   ((file,query,i,name,target) for i,(name,target) in enumerate(candidates)))
    if checks is not None:
        for kind, slots in checks.items():
            for slot, check in slots.items():
                cid = connection.execute("INSERT INTO checks(file,kind,slot,input,suppressed) VALUES(?,?,?,?,?)",
                                         (file,kind,slot,check.get("input"),int(check["suppressed"]))).lastrowid
                for i, finding in enumerate(check["findings"]):
                    args = tuple(finding.get(k, "" if k=="rule" else None) for k in ("code","file","line","message","rule"))
                    connection.execute("INSERT OR IGNORE INTO findings(code,file,line,message,rule) VALUES(?,?,?,?,?)",args)
                    fid = connection.execute("SELECT id FROM findings WHERE code=? AND file=? AND line=? AND message=? AND rule=?",args).fetchone()[0]
                    connection.execute("INSERT INTO check_findings VALUES(?,?,?)",(cid,fid,i))
    connection.executemany("DELETE FROM symbols WHERE id=? AND NOT EXISTS (SELECT 1 FROM names WHERE names.symbol=symbols.id)",old_symbols)
    connection.executemany("DELETE FROM findings WHERE id=? AND NOT EXISTS (SELECT 1 FROM check_findings WHERE finding_id=findings.id)",old_findings)


def write_table(root, rel, value):
    """Replace one file's normalized rows in a transaction, preserving unrelated owners."""
    with _TABLE_LOCK:
        connection = table_connection(root, rel, True)
        # A savepoint also preserves the caller's wider ledger publication transaction.
        connection.execute("SAVEPOINT file_rows")
        try:
            _write_rows(connection,table_location(root,rel)[1],value)
            connection.execute("RELEASE file_rows")
        except BaseException:
            connection.execute("ROLLBACK TO file_rows")
            connection.execute("RELEASE file_rows")
            raise


def read_checks(root, rel):
    """Read only a file's check inputs and findings, without rebuilding other relations."""
    with _TABLE_LOCK:
        connection = table_connection(root, rel)
        if connection is None:
            return None
        file = table_location(root, rel)[1]
        header = connection.execute(
            "SELECT r.source,r.input,d.checker FROM records r "
            "JOIN record_details d ON d.record_file=r.file "
            "WHERE r.file=? AND r.has_checks=1", (file,)).fetchone()
        if header is None:
            return None
        source, inp, checker = header
        result = {"file": source, "input": inp, "checker": checker, "kinds": {}}
        rows = connection.execute(
            "SELECT c.kind,c.slot,c.input,c.suppressed,f.code,f.file,f.line,f.message,f.rule "
            "FROM checks c LEFT JOIN check_findings cf ON cf.check_id=c.id "
            "LEFT JOIN findings f ON f.id=cf.finding_id WHERE c.file=? "
            "ORDER BY c.kind,c.slot,cf.ordinal", (file,))
        for kind, slot, token, suppressed, code, target, line, message, rule in rows:
            check = result["kinds"].setdefault(kind, {}).setdefault(
                slot, {"input": token, "suppressed": suppressed, "findings": []})
            if code is not None:
                check["findings"].append(dict(code=code, file=target, line=line, message=message, rule=rule))
        return result


def write_check(root, rel, kind, slot, value):
    """Replace one changed check and its findings; preserve every other check row."""
    with _TABLE_LOCK:
        connection = table_connection(root, rel)
        if connection is None:
            raise ValueError("check record missing: " + rel)
        file = table_location(root, rel)[1]
        connection.execute("SAVEPOINT check_rows")
        try:
            row = connection.execute("SELECT id FROM checks WHERE file=? AND kind=? AND slot=?", (file, kind, slot)).fetchone()
            if row is None:
                cid = connection.execute(
                    "INSERT INTO checks(file,kind,slot,input,suppressed) VALUES(?,?,?,?,?)",
                    (file, kind, slot, value["input"], int(value["suppressed"]))).lastrowid
            else:
                cid = row[0]
                old = [item[0] for item in connection.execute(
                    "SELECT finding_id FROM check_findings WHERE check_id=?", (cid,))]
                connection.execute("DELETE FROM check_findings WHERE check_id=?", (cid,))
                connection.execute("UPDATE checks SET input=?,suppressed=? WHERE id=?",
                                   (value["input"], int(value["suppressed"]), cid))
            for ordinal, finding in enumerate(value["findings"]):
                args = tuple(finding.get(k, "" if k == "rule" else None)
                             for k in ("code", "file", "line", "message", "rule"))
                connection.execute("INSERT OR IGNORE INTO findings(code,file,line,message,rule) VALUES(?,?,?,?,?)", args)
                fid = connection.execute(
                    "SELECT id FROM findings WHERE code=? AND file=? AND line=? AND message=? AND rule=?", args).fetchone()[0]
                connection.execute("INSERT INTO check_findings VALUES(?,?,?)", (cid, fid, ordinal))
            if row is not None:
                connection.executemany(
                    "DELETE FROM findings WHERE id=? AND NOT EXISTS "
                    "(SELECT 1 FROM check_findings WHERE finding_id=findings.id)",
                    ((fid,) for fid in old))
            connection.execute("RELEASE check_rows")
        except BaseException:
            connection.execute("ROLLBACK TO check_rows")
            connection.execute("RELEASE check_rows")
            raise


def _read_rows(connection, file, owners=None):
    row = connection.execute("SELECT source,input,has_input,relations,has_lookup,has_checks FROM records WHERE file=?",(file,)).fetchone()
    if row is None: return None
    source,inp,has_input,relation,has_lookup,has_checks = row
    roots = relations.select(connection,file,owners=owners).get(None,[])
    if len(roots)!=1: raise ValueError("missing record facts: " + file)
    value = roots[0][1]
    value["file"] = source
    if has_input: value["input"] = inp
    if "watch" in value: value["watch"] = tuple(tuple(v["cells"]) for v in value["watch"])
    if relation:
        names = [name for name, in connection.execute("SELECT s.name FROM names n JOIN symbols s ON s.id=n.symbol WHERE n.file=? ORDER BY n.ordinal",(file,))]
        rows = [(a,b,line,bool(write),bool(guess)) for a,b,line,write,guess in connection.execute("SELECT a.name,b.name,e.line,e.writing,e.guess FROM edges e JOIN symbols a ON a.id=e.source JOIN symbols b ON b.id=e.target WHERE e.file=? ORDER BY e.ordinal",(file,))]
        if relation == "outgoing":
            ids = {name:i for i,name in enumerate(names)}
            value[relation] = {"names":names,"edges":[(ids[a],ids[b],line,write,guess) for a,b,line,write,guess in rows]}
        else: value[relation] = tuple(rows)
    if has_lookup:
        candidates = {}
        for query,name,target in connection.execute("SELECT query,lookup_name,target FROM query_candidates WHERE file=? ORDER BY ordinal",(file,)):
            candidates.setdefault(query,[]).append((name,target))
        value["lookup"] = {}
        for query,shape in connection.execute("SELECT query,shape FROM queries WHERE file=?",(file,)):
            rows = candidates.get(query,[])
            value["lookup"][query] = rows[0][1] if shape=="scalar" else tuple(target for _,target in rows) if shape=="symbols" else tuple(rows)
    if has_checks:
        value["kinds"] = {}
        found = {}
        for cid,code,src,line,message,rule in connection.execute(
                "SELECT cf.check_id,f.code,f.file,f.line,f.message,f.rule FROM checks c JOIN check_findings cf ON cf.check_id=c.id "
                "JOIN findings f ON f.id=cf.finding_id WHERE c.file=? ORDER BY cf.ordinal",(file,)):
            found.setdefault(cid,[]).append(dict(code=code,file=src,line=line,message=message,rule=rule))
        for cid,kind,slot,inp,suppressed in connection.execute("SELECT id,kind,slot,input,suppressed FROM checks WHERE file=?",(file,)):
            value["kinds"].setdefault(kind,{})[slot] = dict(input=inp,findings=found.get(cid,[]),suppressed=suppressed)
    return value


def read_table(root, rel, default, owners=None):
    """Read explicit SQL rows; never deserialize a saved analysis object."""
    with _TABLE_LOCK:
        connection,owned = table_connection(root,rel),False
        if connection is None: return default
        try:
            connection.execute("BEGIN")
            owned = True
            value = _read_rows(connection,table_location(root,rel)[1],owners)
            return default if value is None else value
        except (sqlite3.DatabaseError,ValueError,TypeError,KeyError,IndexError):
            return default
        finally:
            if owned and connection is not None and connection.in_transaction: connection.rollback()


def read_tables(root, rels):
    """Read several file-owned records from each domain with shared typed SQL queries."""
    grouped = {}
    for rel in rels:
        base, file = table_location(root, rel)
        grouped.setdefault(base, {})[file] = rel
    result = {}
    with _TABLE_LOCK:
        for base, paths in grouped.items():
            connection = table_connection(root, next(iter(paths.values())))
            if connection is None:
                continue
            owned = not connection.in_transaction
            try:
                if owned:
                    connection.execute('BEGIN')
                headers = {}
                keys = tuple(paths)
                for start in range(0, len(keys), 400):
                    batch = keys[start:start + 400]
                    marks = ','.join('?' for _ in batch)
                    headers.update((row[0], row[1:]) for row in connection.execute(
                        'SELECT file,source,input,has_input,relations,has_lookup,has_checks '
                        'FROM records WHERE file IN (' + marks + ')', batch))
                if not headers:
                    continue
                roots = relations.select_many(connection, tuple(headers))
                names, edges = {}, {}
                outgoing = tuple(file for file, row in headers.items() if row[3] == 'outgoing')
                for start in range(0, len(outgoing), 400):
                    batch = outgoing[start:start + 400]
                    marks = ','.join('?' for _ in batch)
                    for file, name in connection.execute(
                            'SELECT n.file,s.name FROM names n JOIN symbols s ON s.id=n.symbol '
                            'WHERE n.file IN (' + marks + ') ORDER BY n.file,n.ordinal', batch):
                        names.setdefault(file, []).append(name)
                    for file,a,b,line,writing,guess in connection.execute(
                            'SELECT e.file,a.name,b.name,e.line,e.writing,e.guess FROM edges e '
                            'JOIN symbols a ON a.id=e.source JOIN symbols b ON b.id=e.target '
                            'WHERE e.file IN (' + marks + ') ORDER BY e.file,e.ordinal', batch):
                        edges.setdefault(file, []).append((a,b,line,bool(writing),bool(guess)))
                for file, (source, inp, has_input, relation, has_lookup, has_checks) in headers.items():
                    if relation not in ('', 'outgoing') or has_lookup or has_checks:
                        value = _read_rows(connection, file)
                    else:
                        root_rows = roots.get(file, ())
                        if len(root_rows) != 1:
                            raise ValueError('missing record facts: ' + file)
                        value = root_rows[0][1]
                        value['file'] = source
                        if has_input:
                            value['input'] = inp
                        if 'watch' in value:
                            value['watch'] = tuple(tuple(row['cells']) for row in value['watch'])
                        if relation == 'outgoing':
                            labels = names.get(file, [])
                            ids = {name: index for index, name in enumerate(labels)}
                            value['outgoing'] = {'names': labels, 'edges': [
                                (ids[a], ids[b], line, writing, guess)
                                for a,b,line,writing,guess in edges.get(file, ())]}
                    result[paths[file]] = value
            except (sqlite3.DatabaseError, ValueError, TypeError, KeyError, IndexError):
                # A corrupt domain is not a valid cache. The caller rebuilds its files.
                for rel in paths.values():
                    result.pop(rel, None)
            finally:
                if owned and connection.in_transaction:
                    connection.rollback()
    return result


def table_users(root, folder, keys, kind="query"):
    """Find affected consumers through one domain's persistent reverse indexes."""
    result = set()
    with _TABLE_LOCK:
        connection = table_connection(root,folder+"/_")
        if connection is None: return result
        _,prefix = table_location(root,folder+"/_")
        prefix = prefix[:-1]
        keys = tuple(keys)
        for start in range(0,len(keys),400):
            batch = keys[start:start+400]; slots = ",".join("?" for _ in batch)
            if kind == "query":
                sql = "SELECT r.source FROM queries q JOIN records r ON r.file=q.file WHERE q.query IN (%s)" % slots
            elif kind == "target":
                sql = "SELECT r.source FROM symbols s JOIN edges e ON e.target=s.id JOIN records r ON r.file=e.file WHERE s.name IN (%s)" % slots
            else: raise ValueError("unknown table index")
            sql += " AND r.file>=? AND r.file<?"
            result.update(row[0] for row in connection.execute(sql,(*batch,prefix,prefix+"\uffff")))
    return result


def table_records(root, folder):
    """Enumerate domain records through the file-key index, without walking directories."""
    with _TABLE_LOCK:
        connection = table_connection(root,folder+"/_")
        if connection is None: return []
        base,key = table_location(root,folder+"/_"); prefix=key[:-1]
        records = connection.execute("SELECT file FROM records WHERE file>=? AND file<? ORDER BY file",(prefix,prefix+"\uffff")).fetchall()
        result=[]
        for file, in records:
            rel=os.path.relpath(os.path.join(base,file),root).replace("\\","/")
            value=read_table(root,rel,None)
            if value is None: raise ValueError("invalid table record: " + rel)
            result.append((rel,value))
        return result


def prune_tables(root, folder, live):
    """Delete only disappeared file keys and cascade owned rows in the domain transaction."""
    with _TABLE_LOCK:
        identity=(os.path.abspath(root),folder)
        live={table_location(root,rel)[1] for rel in live}
        previous=_TABLE_LIVE.get(identity)
        if previous==live: return
        connection=table_connection(root,folder+"/_")
        if connection is None: return
        _,prefix=table_location(root,folder+"/_");prefix=prefix[:-1]
        removed=(previous-live) if previous is not None else {file for file, in connection.execute(
            "SELECT file FROM records WHERE file>=? AND file<?",(prefix,prefix+"\uffff"))}-live
        if removed:
            with connection:
                connection.executemany("DELETE FROM records WHERE file=?",((file,) for file in removed))
                connection.execute("DELETE FROM symbols WHERE NOT EXISTS (SELECT 1 FROM names WHERE names.symbol=symbols.id)")
                connection.execute("DELETE FROM findings WHERE NOT EXISTS (SELECT 1 FROM check_findings WHERE finding_id=findings.id)")
        _TABLE_LIVE[identity]=live


def close_tables(root=None):
    """소유 루트의 DB 연결을 닫아 WAL을 마무리하고 파일 핸들을 반환한다."""
    with _TABLE_LOCK:
        if root is None:
            _FILE_ROWS.clear()
            _STATUS_ROWS.clear()
            _STATE_READY.clear()
        else:
            identity = os.path.abspath(root)
            _FILE_ROWS.pop(identity,None)
            _STATUS_ROWS.pop(identity,None)
            _STATE_READY.discard(identity)
        prefix = os.path.abspath(root)+os.sep if root is not None else None
        for path in list(_TABLE_CONNECTIONS):
            if prefix is None or path.startswith(prefix):
                _TABLE_CONNECTIONS.pop(path).close()
        for identity in list(_TABLE_LIVE):
            if root is None or identity[0] == os.path.abspath(root):
                del _TABLE_LIVE[identity]


atexit.register(close_tables)


def now():
    """지금 시각(초까지)."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@contextlib.contextmanager
def locked(root):
    """프로세스 사이 장부 잠금(2.10). 운영체제 파일 잠금이라 잡은 프로세스가 끝나면 풀린다. LOCK_SECONDS까지 기다리고, 못 얻으면 TimeoutError."""
    path = os.path.join(root, LOCK_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handle = open(path, "a+b")
    try:
        deadline = time.time() + LOCK_SECONDS
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.time() >= deadline:
                    raise TimeoutError("장부가 다른 패스에 잠겨 있습니다(%.0f초 기다림): %s" % (LOCK_SECONDS, path))
                time.sleep(0.05)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _state_connection(root, create=False):
    """장부의 헤더·파일 포인터·지적 상태·수신자 행을 같은 트랜잭션으로 소유한다."""
    connection = table_connection(root,LEDGER_FILE,create)
    if connection is None: return None
    return connection


def stamp(root):
    """동일 연결의 변경 수와 외부 커밋 감지를 돌려준다. 별도 세대 번호는 저장하지 않는다."""
    with _TABLE_LOCK:
        connection = _state_connection(root)
        return (connection.total_changes,connection.execute("PRAGMA data_version").fetchone()[0]) if connection else None


def load(root, lazy=False):
    """SQL 장부 헤더·포인터·지적을 읽는다. lazy는 선택된 파일의 선언 행만 조회한다."""
    with _TABLE_LOCK:
        connection = _state_connection(root)
        if connection is None: return None
        connection.execute("BEGIN")
        try:
            saved = _read_rows(connection,"state.row")
            if saved is None: return None
            led = saved["header"]
            rows = dict(connection.execute("SELECT file,row_rel FROM ledger_sources"))
            status = {kind:{} for kind in ("reported","resolved","clients")}
            for kind,key,revision,stamp in connection.execute("SELECT kind,key,revision,time FROM ledger_status"):
                status[kind][key] = dict(rev=revision,time=stamp) if kind == "reported" else revision
        finally:
            connection.rollback()
        files,cached = {},{}
        if lazy:
            files = SourceIndex(root,rows)
            cached = {file:(None,rel,files.versions.get(file)) for file,rel in rows.items()}
        else:
            for file,rel in rows.items():
                saved = read_table(root,rel,None)
                if saved is None: raise ValueError("missing ledger file row: " + file)
                files[file] = saved["entry"]
                cached[file] = (files[file],rel,saved.get('input'))
        led["files"] = files
        led.update(status)
        identity = os.path.abspath(root)
        _FILE_ROWS[identity] = cached
        _STATUS_ROWS[identity] = zlib.compress(marshal.dumps(status), 1)
        return led


def save(root, led, updates=None, change_events=None, metrics=None):
    """변경 원천 행을 먼저 저장한 뒤 헤더·포인터·변경 상태 행을 한 DB 커밋으로 확정한다."""
    started = time.perf_counter()
    metrics = metrics if metrics is not None else {}
    metrics.update(sourceReused=0, sourceRead=0, sourceWritten=0)
    identity = os.path.abspath(root)
    previous = _FILE_ROWS.get(identity,{})
    version = cachemod.POLICY.versions['publication-source']
    current,rows = {},{}
    selected = led["files"]
    for file in selected:
        cached = previous.get(file)
        if isinstance(selected,SourceIndex) and file not in selected.changed and cached is not None and cached[2] == version:
            rows[file] = cached[1]
            current[file] = cached
            metrics['sourceReused'] += 1
            continue
        entry = selected[file]
        if cached is not None and cached[2] == version and (cached[0] is entry or cached[0] == entry):
            rel = cached[1]
            metrics['sourceReused'] += 1
        else:
            digest = cachemod.POLICY.key('publication-source', entry)
            rel = FILE_ROWS + "/" + file + "." + digest + ".row"
            if cached is not None and cached[1] == rel and cached[2] == version:
                metrics['sourceReused'] += 1
            else:
                metrics['sourceRead'] += 1
                stored = read_table(root,rel,None)
                if stored is None or stored.get('input') != version:
                    write_table(root,rel,{"file":file+"|"+digest,"input":version,"entry":entry})
                    metrics['sourceWritten'] += 1
        rows[file] = rel
        current[file] = (entry,rel,version)
    metrics['sourcesSeconds'] = round(time.perf_counter()-started,6)
    status_started = time.perf_counter()
    prior = {}
    if updates is None:
        packed = _STATUS_ROWS.get(identity)
        if packed is not None:
            prior = marshal.loads(zlib.decompress(packed))
        else:
            connection = _state_connection(root)
            if connection is not None:
                for kind,key,revision,stamp in connection.execute('SELECT kind,key,revision,time FROM ledger_status'):
                    prior.setdefault(kind,{})[key] = dict(rev=revision,time=stamp) if kind == 'reported' else revision
    targets = {}
    for kind in ("reported","resolved","clients"):
        old,new = prior.get(kind,{}),led[kind]
        targets[kind] = (set(updates.get(kind,())) if updates is not None else
                        {key for key in old.keys() | new.keys() if key not in old or key not in new or old[key] != new[key]})
    header = {k:v for k,v in led.items() if k not in ("files","reported","resolved","clients")}
    metrics['statusPrepareSeconds'] = round(time.perf_counter()-status_started,6)
    metrics['statusChanged'] = sum(map(len,targets.values()))
    transaction_started = time.perf_counter()
    with _TABLE_LOCK:
        connection = _state_connection(root,True)
        with connection:
            connection.executemany("DELETE FROM ledger_sources WHERE file=?",((file,) for file in previous.keys()-current.keys()))
            connection.executemany("INSERT OR REPLACE INTO ledger_sources VALUES(?,?)",
                ((file,rel) for file,rel in rows.items() if file not in previous or previous[file][1] != rel))
            for kind,keys in targets.items():
                connection.executemany("DELETE FROM ledger_status WHERE kind=? AND key=?",((kind,key) for key in keys if key not in led[kind]))
                connection.executemany("INSERT OR REPLACE INTO ledger_status VALUES(?,?,?,?,?)",
                    ((kind,key,key.split("|",2)[1] if kind != "clients" and "|" in key else "",
                      led[kind][key]["rev"] if kind == "reported" else led[kind][key],
                      led[kind][key]["time"] if kind == "reported" else None)
                     for key in keys if key in led[kind]))
            if change_events is not None:
                revision, stamp, trigger, changes, docs = change_events
                connection.execute("INSERT INTO change_revisions VALUES(?,?,?)", (revision,stamp,trigger))
                connection.executemany(
                    "INSERT INTO code_change_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ((revision,i,c.file,c.path,c.kind,c.symkind,c.name,c.signature,c.line,c.detail,c.base_file)
                     for i,c in enumerate(changes)))
                connection.executemany("INSERT INTO document_change_events VALUES(?,?,?)",
                    ((revision,i,path) for i,path in enumerate(docs)))
            write_table(root,LEDGER_FILE,{"file":"ledger-state","input":str(led["rev"]),"header":header})
    _FILE_ROWS[identity] = current
    if isinstance(selected,SourceIndex):
        selected.rows = rows
        selected.versions = dict.fromkeys(rows,version)
        selected.changed.clear()
    # Explicit changed keys already describe the SQL delta; expanding and packing
    # the whole resolved history is unnecessary. Invalidate the optional diff copy.
    if any(targets.values()):
        _STATUS_ROWS.pop(identity,None)
    metrics['transactionSeconds'] = round(time.perf_counter()-transaction_started,6)
    prune_started = time.perf_counter()
    if any(file not in previous or previous[file][1] != rel for file,rel in rows.items()) or previous.keys() != current.keys():
        prune_tables(root,FILE_ROWS,rows.values())
    metrics['pruneSeconds'] = round(time.perf_counter()-prune_started,6)
    metrics['seconds'] = round(time.perf_counter()-started,6)


def start(manifest, cur, doc_hashes, keys):
    """새 장부. 기준 스냅숏이 있으면 그 색인·지적 열쇠로, 없으면 지금 색인·지금 지적 열쇠로 시작한다."""
    if manifest is not None:
        files, docs, known = manifest["files"], {}, manifest.get("findings") or []
        origin = "기준 스냅숏 " + manifest["name"]
    else:
        files, docs, known = cur, doc_hashes, keys
        origin = "지금 상태"
    return {"origin": origin, "rev": 0, "files": files, "docs": docs,
            "reported": {k: {"rev": 0, "time": now()} for k in known}, "resolved": {}, "clients": {}}


def changed_docs(led, doc_hashes):
    """장부 대비 바뀐(추가·삭제 포함) 문서 경로."""
    old = led.get("docs") or {}
    return sorted(k for k in set(old) | set(doc_hashes) if old.get(k) != doc_hashes.get(k))


def record(root, led, trigger, cur, doc_hashes, changes, docs, keyed, doc_blocked, metrics=None):
    """패스 한 번을 장부·이력에 적는다. keyed = [(열쇠, 지적)]. doc_blocked면(문서 형식 오류로 코드 판정 못 함) 해소를 적지 않는다.
    돌려주는 값: (판, 새 지적 목록, 해소 열쇠 목록)."""
    led["rev"] += 1
    rev, stamp = led["rev"], now()
    present = {k for k, _ in keyed}
    new_keys = {k for k in present if k not in led["reported"]}
    new = [f for k, f in keyed if k in new_keys]
    resolved = [] if doc_blocked else sorted(k for k in led["reported"] if k not in present)
    for k, f in keyed:
        if k not in led["reported"]:
            led["reported"][k] = {"rev": rev, "time": stamp}
            led["resolved"].pop(k, None)
    for k in resolved:
        led["reported"].pop(k, None)
        led["resolved"][k] = rev
    led["files"], led["docs"] = cur, doc_hashes
    line = {"rev": rev, "time": stamp, "trigger": trigger,
            "changes": [{"kind": c.kind, "file": c.file, "path": c.path, "symkind": c.symkind, "name": c.name,
                         "signature": c.signature} for c in changes],
            "docs": docs, "new": sorted(new_keys), "resolved": resolved}
    affected = new_keys | set(resolved)
    save(root, led,{"reported":affected,"resolved":affected,"clients":set()},
         change_events=(rev,stamp,trigger,changes,docs),metrics=metrics)
    path = os.path.join(root, CHANGES_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
    return rev, new, resolved


def since(led, client, current):
    """받는 쪽이 마지막으로 받은 판 뒤의 새 지적(아직 남은 것)과 해소. 받는 쪽의 판을 지금 판으로 올린다.
    current = [(열쇠, 지적 dict)]. 처음 묻는 받는 쪽은 장부를 시작한 판(0)부터 받는다."""
    last = led["clients"].get(client, 0)
    rev = led["rev"]
    led["clients"][client] = rev
    new = [f for k, f in current if (led["reported"].get(k) or {}).get("rev", 0) > last]
    resolved = sorted(k for k, r in led["resolved"].items() if r > last)
    return rev, new, resolved


def diff_since(led, cur, paths=None):
    """장부의 색인 대비 지금 색인의 변경(2.5)."""
    if paths is None: return diffmod.compare(led["files"], cur)
    return diffmod.compare({p:led["files"][p] for p in paths if p in led["files"]},
                           {p:cur[p] for p in paths if p in cur})

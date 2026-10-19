"""Indexed reference queries. Callers pass source/symbol keys, never SQL or connections."""
from storage import ledger

PYTHON_RECORDS = ".spec-conformance/Cache/python-refs"
COMPILATIONS = ".spec-conformance/Cache/refgraph/units/index.row"


def source_edges(root, files):
    """Capture old owned references before any changed extraction replaces cache rows."""
    result = set()
    for file in files:
        if file.endswith('.py'):
            result.update((file,*row) for row in ledger.query_table(root,PYTHON_RECORDS+'/index.row',
                'SELECT a.name,b.name,e.line,e.writing,e.guess FROM records r JOIN edges e ON e.file=r.file '
                'JOIN symbols a ON a.id=e.source JOIN symbols b ON b.id=e.target WHERE r.source=?',(file,)))
        elif file.endswith('.cs'):
            result.update((file,*row,0) for row in ledger.query_table(root,COMPILATIONS,
                'SELECT a.key,b.key,e.line,e.writing FROM compilation_files f JOIN code_references e '
                'ON e.record_file=f.record_file AND e.source_file=f.ordinal '
                'JOIN code_declarations a ON a.record_file=e.record_file AND a.ordinal=e.source '
                'JOIN code_declarations b ON b.record_file=e.record_file AND b.ordinal=e.target WHERE f.path=?',(file,)))
    return result


def source_namespaces(root, inputs, updates=None):
    """Read matching namespace facts or replace only sources whose file stamp changed."""
    with ledger._TABLE_LOCK:
        db = ledger.table_connection(root, ".spec-conformance/Cache/source-namespaces/index.row", True)
        db.execute("CREATE TABLE IF NOT EXISTS namespace_sources(path TEXT PRIMARY KEY,mtime INTEGER,ctime INTEGER,size INTEGER,parser TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS source_namespaces(path TEXT REFERENCES namespace_sources(path) ON DELETE CASCADE,ordinal INTEGER,name TEXT,PRIMARY KEY(path,ordinal))")
        with db:
            for path, names in (updates or {}).items():
                db.execute("DELETE FROM namespace_sources WHERE path=?", (path,))
                db.execute("INSERT INTO namespace_sources VALUES(?,?,?,?,?)", (path,*inputs[path]))
                db.executemany("INSERT INTO source_namespaces VALUES(?,?,?)", ((path,i,name) for i,name in enumerate(names)))
            if updates is not None: return updates
            result = {}
            paths = list(inputs)
            for start in range(0,len(paths),400):
                selected = paths[start:start+400]
                marks = ','.join('?' for _ in selected)
                for path,mtime,ctime,size,parser,name in db.execute(
                        "SELECT s.path,s.mtime,s.ctime,s.size,s.parser,n.name FROM namespace_sources s "
                        "LEFT JOIN source_namespaces n ON n.path=s.path WHERE s.path IN ("+marks+") ORDER BY s.path,n.ordinal",selected):
                    if (mtime,ctime,size,parser) == inputs[path]:
                        names = result.setdefault(path,[])
                        if name is not None: names.append(name)
            return {path:tuple(names) for path,names in result.items()}


def compilation_input(root, record, unit):
    rows = ledger.query_table(root, record, "SELECT input FROM records WHERE source=?", (unit,))
    return rows[0][0] if rows else None


def compilation_summary(root, record, expected_input):
    file = ledger.table_location(root, record)[1]
    rows = ledger.query_table(root, record,
        "SELECT 'header' AS part,0 AS ordinal,c.inputKey,r.input,NULL,NULL FROM records r JOIN compilations c ON c.record_file=r.file WHERE r.file=? "
        "UNION ALL SELECT 'file',ordinal,path,NULL,NULL,NULL FROM compilation_files WHERE record_file=? "
        "UNION ALL SELECT 'diagnostic',ordinal,file,line,code,message FROM code_diagnostics WHERE record_file=? ORDER BY part,ordinal",
        (file, file, file))
    header = [row for row in rows if row[0] == 'header']
    if len(header) != 1 or header[0][2] != expected_input or header[0][3] != expected_input:
        raise ValueError("Compilation record changed or missing: " + record)
    return dict(inputKey=expected_input, files=[row[2] for row in rows if row[0] == 'file'],
                diagnostics=[dict(file=row[2], line=row[3], code=row[4], message=row[5])
                             for row in rows if row[0] == 'diagnostic'])


def compiled_facts(root, files):
    facts = {}
    for file in files:
        if not file.endswith('.cs'):
            continue
        facts.update((key, (name, kind, digest, count)) for key, name, kind, digest, count in
            ledger.query_table(root, COMPILATIONS,
                "SELECT d.key,d.name,d.kind,d.hash,d.stmts FROM compilation_files f JOIN code_declarations d "
                "ON d.record_file=f.record_file AND d.file=f.ordinal WHERE f.path=?", (file,)))
    return facts


def compiled_candidates(root, digests, type_names):
    files = set()
    for digest in digests:
        files.update(p for p, in ledger.query_table(root, COMPILATIONS,
            "SELECT DISTINCT f.path FROM code_declarations d JOIN compilation_files f "
            "ON f.record_file=d.record_file AND f.ordinal=d.file WHERE d.hash=? AND d.stmts>=2", (digest,)))
    for name in type_names:
        files.update(p for p, in ledger.query_table(root, COMPILATIONS,
            "SELECT DISTINCT f.path FROM code_unresolved u JOIN compilation_files f "
            "ON f.record_file=u.record_file AND f.ordinal=u.source_file WHERE u.lookup_name=?", (name,)))
        files.update(p for p, in ledger.query_table(root, COMPILATIONS,
            "SELECT DISTINCT f.path FROM code_declarations d JOIN compilation_files f "
            "ON f.record_file=d.record_file AND f.ordinal=d.file WHERE d.name=?", (name,)))
    return files


def python_member_files(root, names):
    files = set()
    for name in names:
        files.update(file for file, in ledger.query_table(root, PYTHON_RECORDS + '/index.row',
            "SELECT DISTINCT r.source FROM python_declarations d JOIN records r ON r.file=d.record_file "
            "JOIN python_declarations p ON p.record_file=d.record_file AND p.key=d.container "
            "WHERE d.name=? AND p.kind='class'", (name,)))
    return files


def python_imports(root, names):
    rows = set()
    for name in names:
        rows.update(ledger.query_table(root, PYTHON_RECORDS + '/index.row',
            "SELECT r.source,i.kind,i.module,i.name,i.level FROM python_imports i "
            "JOIN records r ON r.file=i.record_file WHERE i.module=? OR i.name=?", (name, name)))
    return sorted(rows)


def python_queries(root, owners):
    return {query for owner in owners for query, in ledger.query_table(root, PYTHON_RECORDS + '/index.row',
        "SELECT query FROM queries q JOIN records r ON r.file=q.file WHERE r.source=?", (owner,))}


def python_closure(root, files):
    """Follow stored edges with indexed joins; do not restore declaration records."""
    with ledger._TABLE_LOCK:
        db = ledger.table_connection(root, PYTHON_RECORDS + '/index.row')
        if db is None:
            return set(files)
        db.execute("SAVEPOINT affected_scope")
        try:
            db.execute("CREATE TEMP TABLE IF NOT EXISTS affected_sources(path TEXT PRIMARY KEY)")
            db.execute("DELETE FROM affected_sources")
            db.executemany("INSERT INTO affected_sources VALUES(?)", ((p,) for p in files))
            result = {p for p, in db.execute("""WITH RECURSIVE
                affected(path) AS (SELECT path FROM affected_sources UNION
                    SELECT substr(s.name,4,instr(substr(s.name,4),':')-1)
                    FROM affected x JOIN records r ON r.source=x.path
                    JOIN edges e ON e.file=r.file JOIN symbols s ON s.id=e.target
                    WHERE s.name LIKE 'py:%' UNION
                    SELECT r.source FROM affected x JOIN symbols s
                      ON s.name >= 'py:'||x.path||':' AND s.name < 'py:'||x.path||':'||char(65535)
                    JOIN edges e ON e.target=s.id JOIN records r ON r.file=e.file)
                SELECT path FROM affected""")}
            db.execute("RELEASE affected_scope")
            return result
        except BaseException:
            db.execute("ROLLBACK TO affected_scope")
            db.execute("RELEASE affected_scope")
            raise

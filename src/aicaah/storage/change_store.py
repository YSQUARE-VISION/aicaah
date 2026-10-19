"""Committed source changes and diagnosis cursors in one normalized SQL database."""
import hashlib
from storage import ledger

ANCHOR = ledger.STATE_ROOT + '/source-commits.row'
DDL = '''
CREATE TABLE IF NOT EXISTS source_commits(id INTEGER PRIMARY KEY AUTOINCREMENT,basis TEXT NOT NULL,created TEXT NOT NULL,error TEXT NOT NULL,diagnosed INTEGER NOT NULL DEFAULT 0,published INTEGER NOT NULL DEFAULT 0,superseded INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS source_commit_files(commit_id INTEGER REFERENCES source_commits(id),file TEXT NOT NULL,before_record TEXT REFERENCES records(file),after_record TEXT REFERENCES records(file),changed INTEGER NOT NULL,PRIMARY KEY(commit_id,file));
CREATE TABLE IF NOT EXISTS source_commit_impacts(commit_id INTEGER REFERENCES source_commits(id),file TEXT NOT NULL,side TEXT NOT NULL,PRIMARY KEY(commit_id,file,side));
CREATE TABLE IF NOT EXISTS source_commit_edges(commit_id INTEGER REFERENCES source_commits(id),side TEXT NOT NULL,ordinal INTEGER NOT NULL,owner TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,line INTEGER NOT NULL,writing INTEGER NOT NULL,guessed INTEGER NOT NULL,PRIMARY KEY(commit_id,side,ordinal));
CREATE TABLE IF NOT EXISTS source_commit_graph_flags(commit_id INTEGER REFERENCES source_commits(id),kind TEXT NOT NULL,ordinal INTEGER NOT NULL,a INTEGER,b INTEGER,c INTEGER,d INTEGER,e INTEGER,PRIMARY KEY(commit_id,kind,ordinal));
CREATE TABLE IF NOT EXISTS source_commit_lookups(commit_id INTEGER REFERENCES source_commits(id),query TEXT NOT NULL,file TEXT NOT NULL,PRIMARY KEY(commit_id,query,file));
CREATE TABLE IF NOT EXISTS source_commit_units(commit_id INTEGER REFERENCES source_commits(id),ordinal INTEGER NOT NULL,record TEXT NOT NULL REFERENCES records(file),input TEXT,variant TEXT,PRIMARY KEY(commit_id,ordinal));
CREATE TABLE IF NOT EXISTS source_commit_owners(commit_id INTEGER,unit INTEGER,ordinal INTEGER,path TEXT NOT NULL,PRIMARY KEY(commit_id,unit,ordinal),FOREIGN KEY(commit_id,unit) REFERENCES source_commit_units(commit_id,ordinal));
CREATE TABLE IF NOT EXISTS diagnosis_state(id INTEGER PRIMARY KEY CHECK(id=1),head INTEGER NOT NULL,completed INTEGER NOT NULL,published INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS diagnosis_current(finding_id INTEGER PRIMARY KEY REFERENCES findings(id),commit_id INTEGER NOT NULL REFERENCES source_commits(id));
CREATE TABLE IF NOT EXISTS diagnosis_changes(commit_id INTEGER REFERENCES source_commits(id),finding_id INTEGER REFERENCES findings(id),operation TEXT NOT NULL,PRIMARY KEY(commit_id,finding_id));
CREATE TABLE IF NOT EXISTS diagnosis_node_status(commit_id INTEGER REFERENCES source_commits(id),decl INTEGER,status TEXT NOT NULL,PRIMARY KEY(commit_id,decl));
CREATE TABLE IF NOT EXISTS diagnosis_bad_edges(commit_id INTEGER REFERENCES source_commits(id),source INTEGER,target INTEGER,PRIMARY KEY(commit_id,source,target));
CREATE TABLE IF NOT EXISTS source_commit_rechecks(commit_id INTEGER PRIMARY KEY REFERENCES source_commits(id),revision INTEGER NOT NULL,basis TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_commit_pending ON source_commits(published,superseded,id);
CREATE INDEX IF NOT EXISTS source_commit_owner ON source_commit_files(file,commit_id);
'''


def connection(root):
    """Initialize the change journal beside the existing ledger, without a second DB."""
    db = ledger.table_connection(root, ANCHOR, True)
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='source_commits'").fetchone():
        with db:
            for sql in DDL.split(';'):
                if sql.strip(): db.execute(sql)
            db.execute('INSERT INTO diagnosis_state VALUES(1,0,0,0)')
    return db


def commit(root, basis, before, after, before_scope, after_scope, graph, old_edges=(), units=(), reference_scope=None):
    """Atomically commit immutable source facts, both impact sets and reference facts."""
    graph = vars(graph) if not isinstance(graph, dict) else graph
    fields = ('files','decls','edges','overrides','strings','unresolved','diagnostics','units')
    data = {key:graph.get(key,[]) for key in fields}
    # All parsing, dependency traversal and compilation decoding precede BEGIN.
    sources = {}
    for file in set(before) | set(after):
        for entry in (before.get(file),after.get(file)):
            if entry is not None:
                key = 'source-version/' + hashlib.sha256((file+'\0'+repr(entry)).encode()).hexdigest()
                sources[(file,id(entry))] = (key,entry)
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            db.execute('BEGIN IMMEDIATE')
            cid = db.execute('INSERT INTO source_commits(basis,created,error) VALUES(?,?,?)',
                             (basis,ledger.now(),graph.get('error',''))).lastrowid
            for key,entry in sources.values():
                if not db.execute('SELECT 1 FROM records WHERE file=?',(key,)).fetchone():
                    ledger._write_rows(db,key,{'file':key,'entry':entry})
            for file in sorted(set(before)|set(after)|set(before_scope)|set(after_scope)):
                old,new = before.get(file),after.get(file)
                a = sources[(file,id(old))][0] if old is not None else None
                b = sources[(file,id(new))][0] if new is not None else None
                changed = old is None or new is None or old.get('sha256') != new.get('sha256')
                db.execute('INSERT INTO source_commit_files VALUES(?,?,?,?,?)',(cid,file,a,b,int(changed)))
            db.executemany('INSERT INTO source_commit_impacts VALUES(?,?,?)',
                ((cid,file,side) for side,files in (('before',before_scope),('after',after_scope),
                    ('references',after_scope if reference_scope is None else reference_scope)) for file in sorted(files)))
            ledger._write_rows(db,f'commit/{cid}/graph',{'file':f'commit/{cid}/graph','data':data})
            edges = list(old_edges)
            db.executemany('INSERT INTO source_commit_edges VALUES(?,?,?,?,?,?,?,?,?)',
                ((cid,'before',i,*row) for i,row in enumerate(edges)))
            edges = [(data['files'][f],data['decls'][a]['key'],data['decls'][b]['key'],line,int(w),
                      int((a,b,f,line) in graph.get('guessed',()))) for a,b,f,line,w in data['edges']]
            db.executemany('INSERT INTO source_commit_edges VALUES(?,?,?,?,?,?,?,?,?)',
                ((cid,'after',i,*row) for i,row in enumerate(edges)))
            db.executemany('INSERT INTO source_commit_graph_flags VALUES(?,?,?,?,?,?,?,?)',
                ((cid,kind,i,*tuple(row),*([None]*(5-len(row)))) for kind in ('guessed','execution_edges')
                 for i,row in enumerate(sorted(graph.get(kind,())))))
            db.executemany('INSERT INTO source_commit_lookups VALUES(?,?,?)',
                ((cid,query,file) for query,files in graph.get('lookup_users',{}).items() for file in sorted(files)))
            for i,unit in enumerate(units):
                key = f'commit/{cid}/unit/{i}'
                ledger._write_rows(db,key,{'file':key,'input':unit['inputKey'],'data':unit['data']})
                db.execute('INSERT INTO source_commit_units VALUES(?,?,?,?,?)',(cid,i,key,unit['inputKey'],unit.get('variant')))
                db.executemany('INSERT INTO source_commit_owners VALUES(?,?,?,?)',((cid,i,n,p) for n,p in enumerate(unit['owners'])))
            db.execute('UPDATE diagnosis_state SET head=? WHERE id=1',(cid,))
        return cid


def pending(root, basis):
    """Return an unpublished committed input; never derive work from process memory."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        row = db.execute('SELECT id,basis,diagnosed FROM source_commits WHERE published=0 AND superseded=0 ORDER BY id DESC LIMIT 1').fetchone()
        if row is None: return None
        cid,stored,done = row
        files = {p for p, in db.execute('SELECT file FROM source_commit_files WHERE commit_id=? AND changed=1',(cid,))}
        impacts = {p for p, in db.execute("SELECT file FROM source_commit_impacts WHERE commit_id=? AND side IN ('before','after')",(cid,))}
        references = {p for p, in db.execute("SELECT file FROM source_commit_impacts WHERE commit_id=? AND side='references'",(cid,))}
        return dict(id=cid,basis=stored,compatible=stored==basis,diagnosed=bool(done),changed=files,scope=impacts,referenceScope=references)


def read(root, cid):
    """Read exactly one committed input in a SQLite read snapshot."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        db.execute('BEGIN')
        try:
            head = db.execute('SELECT basis,error,diagnosed FROM source_commits WHERE id=?',(cid,)).fetchone()
            if head is None: raise KeyError(cid)
            before,after = {},{}
            for file,a,b in db.execute('SELECT file,before_record,after_record FROM source_commit_files WHERE commit_id=?',(cid,)):
                for target,key in ((before,a),(after,b)):
                    if key is not None: target[file] = ledger._read_rows(db,key)['entry']
            graph = ledger._read_rows(db,f'commit/{cid}/graph')['data']
            graph['error'],graph['guessed'],graph['execution_edges'],graph['lookup_users'] = head[1],set(),set(),{}
            for kind,a,b,c,d,e in db.execute('SELECT kind,a,b,c,d,e FROM source_commit_graph_flags WHERE commit_id=? ORDER BY ordinal',(cid,)):
                graph[kind].add((a,b,c,d) if kind=='guessed' else (a,b,c,d,e))
            for query,file in db.execute('SELECT query,file FROM source_commit_lookups WHERE commit_id=?',(cid,)):
                graph['lookup_users'].setdefault(query,set()).add(file)
            graph['compilations'] = []
            for n,key,inp,variant in db.execute('SELECT ordinal,record,input,variant FROM source_commit_units WHERE commit_id=? ORDER BY ordinal',(cid,)):
                facts = ledger._read_rows(db,key)['data']
                owners = [p for p, in db.execute('SELECT path FROM source_commit_owners WHERE commit_id=? AND unit=? ORDER BY ordinal',(cid,n))]
                item = dict(owners=owners,files=facts['files'],inputKey=inp,
                            data=dict(root=root,record=ledger.STATE_ROOT+'/'+key,input=inp))
                if variant is not None: item['variant'] = variant
                graph['compilations'].append(item)
            findings = [tuple(row) for row in db.execute('SELECT f.code,f.file,f.line,f.message,f.rule FROM diagnosis_current c JOIN findings f ON f.id=c.finding_id ORDER BY f.file,f.line,f.code,f.message,f.rule')] if head[2] else []
            status = dict(db.execute('SELECT decl,status FROM diagnosis_node_status WHERE commit_id=?',(cid,)))
            bad = set(db.execute('SELECT source,target FROM diagnosis_bad_edges WHERE commit_id=?',(cid,)))
            old_edges = [tuple(row) for row in db.execute(
                "SELECT owner,source,target,line,writing,guessed FROM source_commit_edges WHERE commit_id=? AND side='before' ORDER BY ordinal",(cid,))]
            return dict(id=cid,basis=head[0],before=before,after=after,graph=graph,findings=findings,diagnosed=bool(head[2]),status=status,bad_edges=bad,before_edges=old_edges)
        finally:
            db.rollback()


def complete(root, cid, findings, previous, status=None, bad_edges=()):
    """Commit finding differences and the completed cursor together, rejecting stale work."""
    desired = set(map(tuple,findings))
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            db.execute('BEGIN IMMEDIATE')
            head,completed = db.execute('SELECT head,completed FROM diagnosis_state WHERE id=1').fetchone()
            if head != cid: return False
            if completed == cid: return True
            # The first journal result adopts the already published findings;
            # subsequent results touch only changed finding identities.
            existing = set(db.execute('SELECT f.code,f.file,f.line,f.message,f.rule FROM diagnosis_current c JOIN findings f ON f.id=c.finding_id'))
            for item in desired-existing:
                db.execute('INSERT OR IGNORE INTO findings(code,file,line,message,rule) VALUES(?,?,?,?,?)',item)
                fid = db.execute('SELECT id FROM findings WHERE code=? AND file=? AND line=? AND message=? AND rule=?',item).fetchone()[0]
                db.execute('INSERT OR REPLACE INTO diagnosis_current VALUES(?,?)',(fid,cid))
                db.execute('INSERT INTO diagnosis_changes VALUES(?,?,?)',(cid,fid,'add'))
            for item in existing-desired:
                row = db.execute('SELECT id FROM findings WHERE code=? AND file=? AND line=? AND message=? AND rule=?',item).fetchone()
                if row:
                    db.execute('DELETE FROM diagnosis_current WHERE finding_id=?',row)
                    db.execute('INSERT INTO diagnosis_changes VALUES(?,?,?)',(cid,row[0],'remove'))
            db.execute('UPDATE source_commits SET diagnosed=1 WHERE id=?',(cid,))
            db.executemany('INSERT INTO diagnosis_node_status VALUES(?,?,?)',((cid,k,v) for k,v in (status or {}).items()))
            db.executemany('INSERT INTO diagnosis_bad_edges VALUES(?,?,?)',((cid,a,b) for a,b in bad_edges))
            db.execute('UPDATE source_commits SET superseded=1 WHERE id<? AND published=0',(cid,))
            db.execute('UPDATE diagnosis_state SET completed=? WHERE id=1',(cid,))
        return True


def acknowledge(root, cid):
    """Advance the projection cursor only after the committed result is published."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT head,completed FROM diagnosis_state WHERE id=1').fetchone()
            if row != (cid,cid): raise ValueError('stale diagnosis publication')
            db.execute('UPDATE source_commits SET published=1 WHERE id=?',(cid,))
            db.execute('UPDATE diagnosis_state SET published=? WHERE id=1',(cid,))


def rechecked(root, cid, revision, basis):
    """Close an invalidated input only after a current complete-scope pass was published."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            db.execute('BEGIN IMMEDIATE')
            head = db.execute('SELECT head FROM diagnosis_state WHERE id=1').fetchone()[0]
            if head != cid: raise ValueError('new input appeared during recheck publication')
            db.execute('INSERT OR REPLACE INTO source_commit_rechecks VALUES(?,?,?)',(cid,revision,basis))
            db.execute('UPDATE source_commits SET superseded=1 WHERE id<=? AND published=0',(cid,))

"""Document folders, declaration rows and architecture relationships in SQL (SPEC-36)."""
import hashlib
import os
import contextlib
from storage import ledger

ANCHOR = ".spec-conformance/Cache/design/structure.row"
DDL = """
CREATE TABLE IF NOT EXISTS workspace_roots(id INTEGER PRIMARY KEY,absolute_path TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS directories(id INTEGER PRIMARY KEY,root_id INTEGER NOT NULL REFERENCES workspace_roots(id),
 parent_id INTEGER REFERENCES directories(id),name TEXT NOT NULL,path TEXT NOT NULL,UNIQUE(root_id,path));
CREATE INDEX IF NOT EXISTS directory_parent ON directories(parent_id);
CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY,root_id INTEGER NOT NULL REFERENCES workspace_roots(id),
 directory_id INTEGER NOT NULL REFERENCES directories(id),name TEXT NOT NULL,path TEXT NOT NULL,
 mtime INTEGER,size INTEGER,ctime INTEGER,parser TEXT NOT NULL,source TEXT NOT NULL,UNIQUE(root_id,path));
CREATE TABLE IF NOT EXISTS document_rows(id INTEGER PRIMARY KEY,document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,line INTEGER NOT NULL,kind TEXT NOT NULL,UNIQUE(document_id,ordinal));
CREATE INDEX IF NOT EXISTS document_row_kind ON document_rows(kind,document_id);
CREATE TABLE IF NOT EXISTS document_cells(row_id INTEGER NOT NULL REFERENCES document_rows(id) ON DELETE CASCADE,
 column_name TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(row_id,column_name));
CREATE TABLE IF NOT EXISTS document_parse_issues(id INTEGER PRIMARY KEY,document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,row_ordinal INTEGER,code TEXT,file TEXT,line INTEGER,message TEXT);
CREATE TABLE IF NOT EXISTS document_members(row_id INTEGER PRIMARY KEY REFERENCES document_rows(id) ON DELETE CASCADE,
 signature TEXT,name TEXT,params TEXT,stable_key TEXT,path TEXT,kind TEXT,has_kind INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS document_diagrams(id INTEGER PRIMARY KEY,row_id INTEGER NOT NULL UNIQUE REFERENCES document_rows(id) ON DELETE CASCADE,
 local_key TEXT NOT NULL,diagram_type TEXT NOT NULL,source_hash TEXT NOT NULL,semantic_hash TEXT);
CREATE TABLE IF NOT EXISTS diagram_source_lines(diagram_id INTEGER NOT NULL REFERENCES document_diagrams(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL,line INTEGER NOT NULL,text TEXT NOT NULL,PRIMARY KEY(diagram_id,ordinal));
CREATE TABLE IF NOT EXISTS diagram_groups(id INTEGER PRIMARY KEY,diagram_id INTEGER NOT NULL REFERENCES document_diagrams(id) ON DELETE CASCADE,
 parent_id INTEGER REFERENCES diagram_groups(id),local_key TEXT NOT NULL,label TEXT NOT NULL,line INTEGER NOT NULL,UNIQUE(diagram_id,local_key));
CREATE TABLE IF NOT EXISTS diagram_nodes(id INTEGER PRIMARY KEY,diagram_id INTEGER NOT NULL REFERENCES document_diagrams(id) ON DELETE CASCADE,
 local_key TEXT NOT NULL,label TEXT NOT NULL,line INTEGER NOT NULL,UNIQUE(diagram_id,local_key));
CREATE TABLE IF NOT EXISTS diagram_group_members(group_id INTEGER NOT NULL REFERENCES diagram_groups(id) ON DELETE CASCADE,
 node_id INTEGER NOT NULL REFERENCES diagram_nodes(id) ON DELETE CASCADE,PRIMARY KEY(group_id,node_id));
CREATE TABLE IF NOT EXISTS diagram_edges(id INTEGER PRIMARY KEY,diagram_id INTEGER NOT NULL REFERENCES document_diagrams(id) ON DELETE CASCADE,
 source_id INTEGER NOT NULL REFERENCES diagram_nodes(id) ON DELETE CASCADE,target_id INTEGER NOT NULL REFERENCES diagram_nodes(id) ON DELETE CASCADE,
 relation_kind TEXT NOT NULL,line INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS diagram_edge_target ON diagram_edges(target_id);
CREATE TABLE IF NOT EXISTS diagram_aliases(node_id INTEGER PRIMARY KEY REFERENCES diagram_nodes(id) ON DELETE CASCADE,
 target_diagram TEXT NOT NULL,target_node TEXT NOT NULL,resolved_node_id INTEGER REFERENCES diagram_nodes(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS design_entities(id INTEGER PRIMARY KEY,root_id INTEGER NOT NULL REFERENCES workspace_roots(id),
 stable_key TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,parent_id INTEGER REFERENCES design_entities(id),UNIQUE(root_id,stable_key));
CREATE TABLE IF NOT EXISTS modules(entity_id INTEGER PRIMARY KEY REFERENCES design_entities(id) ON DELETE CASCADE,
 parent_module_id INTEGER REFERENCES modules(entity_id));
CREATE TABLE IF NOT EXISTS module_code_directories(module_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE,
 directory_id INTEGER NOT NULL REFERENCES directories(id),include_descendants INTEGER NOT NULL,PRIMARY KEY(module_id,directory_id));
CREATE TABLE IF NOT EXISTS module_spec_directories(module_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE,
 directory_id INTEGER NOT NULL REFERENCES directories(id),PRIMARY KEY(module_id,directory_id));
CREATE TABLE IF NOT EXISTS document_assignments(document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 module_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE,role TEXT NOT NULL,PRIMARY KEY(document_id,module_id,role));
CREATE TABLE IF NOT EXISTS document_entity_sections(row_id INTEGER PRIMARY KEY REFERENCES document_rows(id) ON DELETE CASCADE,
 entity_id INTEGER NOT NULL REFERENCES design_entities(id) ON DELETE CASCADE,section_role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS diagram_entity_links(node_id INTEGER PRIMARY KEY REFERENCES diagram_nodes(id) ON DELETE CASCADE,
 entity_id INTEGER NOT NULL REFERENCES design_entities(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS diagram_directory_links(node_id INTEGER PRIMARY KEY REFERENCES diagram_nodes(id) ON DELETE CASCADE,
 directory_id INTEGER NOT NULL REFERENCES directories(id));
CREATE TABLE IF NOT EXISTS diagram_module_links(node_id INTEGER PRIMARY KEY REFERENCES diagram_nodes(id) ON DELETE CASCADE,
 module_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS module_dependencies(source_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE,
 target_id INTEGER NOT NULL REFERENCES modules(entity_id) ON DELETE CASCADE,relation_kind TEXT NOT NULL,PRIMARY KEY(source_id,target_id,relation_kind));
CREATE TABLE IF NOT EXISTS code_files(id INTEGER PRIMARY KEY,root_id INTEGER NOT NULL REFERENCES workspace_roots(id),
 directory_id INTEGER NOT NULL REFERENCES directories(id),path TEXT NOT NULL,input TEXT NOT NULL,UNIQUE(root_id,path));
CREATE TABLE IF NOT EXISTS code_nodes(id INTEGER PRIMARY KEY,file_id INTEGER NOT NULL REFERENCES code_files(id) ON DELETE CASCADE,
 stable_key TEXT NOT NULL,owner_path TEXT NOT NULL,name TEXT NOT NULL,kind TEXT NOT NULL,signature TEXT NOT NULL,
 line INTEGER NOT NULL,UNIQUE(file_id,stable_key));
CREATE INDEX IF NOT EXISTS code_node_member ON code_nodes(file_id,owner_path,name,kind,signature);
CREATE TABLE IF NOT EXISTS design_code_links(entity_id INTEGER NOT NULL REFERENCES design_entities(id) ON DELETE CASCADE,
 code_node_id INTEGER NOT NULL REFERENCES code_nodes(id) ON DELETE CASCADE,relation_kind TEXT NOT NULL,PRIMARY KEY(entity_id,code_node_id));
CREATE TABLE IF NOT EXISTS link_expectations(row_id INTEGER PRIMARY KEY REFERENCES document_rows(id) ON DELETE CASCADE,
 entity_id INTEGER REFERENCES design_entities(id) ON DELETE CASCADE,selector TEXT NOT NULL,target_file TEXT,target_owner TEXT,target_name TEXT,target_kind TEXT,signature TEXT);
CREATE INDEX IF NOT EXISTS link_target_file ON link_expectations(target_file);
CREATE TABLE IF NOT EXISTS design_changes(id INTEGER PRIMARY KEY,document_path TEXT NOT NULL,
 line INTEGER,operation TEXT NOT NULL,field TEXT NOT NULL,old_value TEXT,new_value TEXT,changed_at TEXT NOT NULL);
"""


def connection(root):
    root = os.path.abspath(root).split(os.sep + ".spec-conformance" + os.sep, 1)[0]
    db = ledger.table_connection(root, ANCHOR, True)
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='workspace_roots'").fetchone():
        with db:
            for sql in DDL.split(';'):
                if sql.strip(): db.execute(sql)
    db.execute("CREATE INDEX IF NOT EXISTS link_target_file ON link_expectations(target_file)")
    db.execute("CREATE TABLE IF NOT EXISTS document_reference_inputs(document_id INTEGER PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE)")
    db.execute("CREATE TABLE IF NOT EXISTS document_references(document_id INTEGER REFERENCES document_reference_inputs(document_id) ON DELETE CASCADE,ordinal INTEGER,line INTEGER,kind TEXT,owner TEXT,name TEXT,PRIMARY KEY(document_id,ordinal))")
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='contract_states'").fetchone():
        db.executescript("""
        CREATE TABLE contract_states(root_id INTEGER PRIMARY KEY REFERENCES workspace_roots(id),input TEXT NOT NULL,suppressed INTEGER NOT NULL,structure TEXT NOT NULL);
        CREATE TABLE contract_documents(root_id INTEGER REFERENCES contract_states(root_id) ON DELETE CASCADE,document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,ordinal INTEGER,is_design INTEGER,PRIMARY KEY(root_id,document_id));
        CREATE TABLE contract_issues(root_id INTEGER REFERENCES contract_states(root_id) ON DELETE CASCADE,ordinal INTEGER,code TEXT,file TEXT,line INTEGER,message TEXT,PRIMARY KEY(root_id,ordinal));
        CREATE TABLE contract_sources(root_id INTEGER REFERENCES contract_states(root_id) ON DELETE CASCADE,file TEXT,mtime INTEGER,ctime INTEGER,size INTEGER,PRIMARY KEY(root_id,file));
        CREATE TABLE contract_targets(row_id INTEGER REFERENCES document_rows(id) ON DELETE CASCADE,file TEXT,role TEXT,PRIMARY KEY(row_id,file,role));
        CREATE INDEX contract_target_file ON contract_targets(file,row_id);
        CREATE TABLE contract_architecture(row_id INTEGER PRIMARY KEY REFERENCES document_rows(id) ON DELETE CASCADE,node_key TEXT,owner_key TEXT,declaration_key TEXT,declaration_sig TEXT,folder TEXT,member_file TEXT,member_owner TEXT,member_name TEXT,member_kind TEXT,signature TEXT,external INTEGER,input_hash TEXT,module_key TEXT,has_entries INTEGER);
        CREATE INDEX contract_architecture_node ON contract_architecture(node_key);
        CREATE TABLE contract_architecture_edges(row_id INTEGER REFERENCES document_rows(id) ON DELETE CASCADE,ordinal INTEGER,source TEXT,relation TEXT,target TEXT,doc TEXT,line INTEGER,PRIMARY KEY(row_id,ordinal));
        CREATE INDEX contract_architecture_edge_target ON contract_architecture_edges(target);
        CREATE TABLE contract_architecture_members(row_id INTEGER REFERENCES document_rows(id) ON DELETE CASCADE,ordinal INTEGER,member_key TEXT,signature TEXT,PRIMARY KEY(row_id,ordinal));
        CREATE TABLE contract_architecture_locations(row_id INTEGER REFERENCES document_rows(id) ON DELETE CASCADE,ordinal INTEGER,doc TEXT,line INTEGER,PRIMARY KEY(row_id,ordinal));
        CREATE TABLE contract_architecture_files(row_id INTEGER REFERENCES document_rows(id) ON DELETE CASCADE,file TEXT,PRIMARY KEY(row_id,file));
        CREATE INDEX document_cell_value ON document_cells(column_name,value,row_id);
        """)
    return db


def contract_state(root, source_root, fingerprint, ds=None):
    """Publish validated document contracts, or restore their identity without reading document payloads."""
    import re
    source = os.path.normcase(os.path.abspath(source_root))
    with ledger._TABLE_LOCK:
        db = connection(root)
        rid = db.execute("SELECT id FROM workspace_roots WHERE absolute_path=?",(source,)).fetchone()
        if not rid:
            return None
        rid = rid[0]
        saved = db.execute("SELECT input,suppressed,structure FROM contract_states WHERE root_id=?",(rid,)).fetchone()
        dependencies = dict()
        if saved and saved[0] == fingerprint:
            valid = True
            for file,mtime,ctime,size in db.execute("SELECT file,mtime,ctime,size FROM contract_sources WHERE root_id=?",(rid,)):
                try:
                    st = os.stat(os.path.join(root,file)); stamp = (st.st_mtime_ns,st.st_ctime_ns,st.st_size)
                except OSError:
                    stamp = (None,None,None)
                if stamp != (mtime,ctime,size): valid = False
            if valid:
                return dict(input=fingerprint,root_id=rid,suppressed=saved[1],structure=saved[2],
                    issues=list(db.execute("SELECT code,file,line,message FROM contract_issues WHERE root_id=? ORDER BY ordinal",(rid,))),
                    design_docs={path for path, in db.execute("SELECT d.path FROM contract_documents c JOIN documents d ON d.id=c.document_id WHERE c.root_id=? AND c.is_design=1",(rid,))},
                    counts=dict(db.execute("SELECT r.kind,count(*) FROM contract_documents c JOIN document_rows r ON r.document_id=c.document_id WHERE c.root_id=? GROUP BY r.kind",(rid,))))
        if ds is None:
            return None
        structure = hashlib.sha256()
        for row in ds.rows:
            structure.update(repr((row.doc,row.kind,row.line,sorted(row.cells.items()))).encode('utf-8'))
            if row.kind in {'architecture','architecture-graph'}:
                structure.update(row.parsed.get('inputHash','').encode('ascii'))
            structure.update(b'\0')
            if row.kind == 'members' and row.cells['종류'] in {'class','struct','interface','enum','record','delegate'} and row.cells['파일'].endswith('.cs'):
                file = row.cells['파일']
                try:
                    st=os.stat(os.path.join(root,file)); dependencies[file]=(st.st_mtime_ns,st.st_ctime_ns,st.st_size)
                except OSError:
                    dependencies[file]=(None,None,None)
        for issue in ds.issues:
            structure.update(repr((issue.code,issue.file,issue.line,issue.message)).encode('utf-8')); structure.update(b'\0')
        structure.update(repr(ds.suppressed).encode('utf-8'))
        design_docs={path for path,lines in ds.texts.items() if any(re.match(r'^\s*\|\s*상태\s*\|\s*(?:설계중|설계완료)(?:\s|—|·|\|)',line) for line in lines)}
        with db:
            db.execute("DELETE FROM contract_states WHERE root_id=?",(rid,))
            db.execute("INSERT INTO contract_states VALUES(?,?,?,?)",(rid,fingerprint,ds.suppressed,structure.hexdigest()))
            ids={path:did for did,path in db.execute("SELECT id,path FROM documents WHERE root_id=?",(rid,))}
            db.executemany("INSERT INTO contract_documents VALUES(?,?,?,?)",((rid,ids[path],i,int(path in design_docs)) for i,path in enumerate(ds.docs)))
            db.executemany("INSERT INTO contract_issues VALUES(?,?,?,?,?,?)",((rid,i,x.code,x.file,x.line,x.message) for i,x in enumerate(ds.issues)))
            db.executemany("INSERT INTO contract_sources VALUES(?,?,?,?,?)",((rid,file,*stamp) for file,stamp in dependencies.items()))
            row_ids={(path,line,kind):row_id for row_id,path,line,kind in db.execute("SELECT r.id,d.path,r.line,r.kind FROM contract_documents c JOIN documents d ON d.id=c.document_id JOIN document_rows r ON r.document_id=d.id WHERE c.root_id=?",(rid,))}
            for table in ('contract_targets','contract_architecture','contract_architecture_edges','contract_architecture_members','contract_architecture_locations','contract_architecture_files'):
                db.execute('DELETE FROM '+table+' WHERE row_id IN (SELECT r.id FROM document_rows r JOIN documents d ON d.id=r.document_id WHERE d.root_id=?)',(rid,))
            for row in ds.rows:
                row_id=row_ids[(row.doc,row.line,row.kind)]; p=row.parsed
                targets=set()
                file=row.cells.get('파일')
                if file: targets.add((file,'pattern' if any(x in file for x in '*?[') else 'file'))
                if row.kind == 'behaviors':
                    for col in ('구현 대상','검사 연결'):
                        targets.update((s.strip().partition('#')[0],'behavior') for s in row.cells[col].split(',') if s.strip() not in ('','-'))
                if p and row.kind in {'members','body','changes'}:
                    db.execute("INSERT OR REPLACE INTO document_members VALUES(?,?,?,?,?,?,?,?)",(row_id,*(p.get(k) for k in ('signature','name','params','key','path','kind')),int('kind' in p)))
                if row.kind == 'architecture':
                    key=p.get('declarationKey'); pair=isinstance(key,(list,tuple))
                    db.execute("INSERT INTO contract_architecture VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(row_id,p.get('nodeKey'),p.get('ownerKey'),key[0] if pair else key,key[1] if pair else None,*(p.get(k) for k in ('folder','memberFile','memberOwner','memberName','memberKind','signature','external','inputHash','moduleKey')),int('entryMembers' in p)))
                    db.executemany("INSERT INTO contract_architecture_edges VALUES(?,?,?,?,?,?,?)",((row_id,i,*edge) for i,edge in enumerate(p.get('edges',()))))
                    db.executemany("INSERT INTO contract_architecture_members VALUES(?,?,?,?)",((row_id,i,*m) for i,m in enumerate(p.get('entryMembers',()))))
                    db.executemany("INSERT INTO contract_architecture_locations VALUES(?,?,?,?)",((row_id,i,*loc) for i,loc in enumerate(p.get('sourceLocations',()))))
                    db.executemany("INSERT INTO contract_architecture_files VALUES(?,?)",((row_id,f) for f in p.get('affectedFiles',())))
                    if p.get('memberFile'): targets.add((p['memberFile'],'architecture'))
                    targets.update((m[0].split('|')[0],'architecture') for m in p.get('entryMembers',()))
                db.executemany("INSERT INTO contract_targets VALUES(?,?,?)",((row_id,*t) for t in targets))
        return contract_state(root,source_root,fingerprint)


@contextlib.contextmanager
def contract_snapshot(root, state):
    """Hold the validated basis and requested rows in one SQL read snapshot."""
    with ledger._TABLE_LOCK:
        db=connection(root)
        db.execute('SAVEPOINT document_contract_read')
        try:
            if db.execute('SELECT input FROM contract_states WHERE root_id=?',(state['root_id'],)).fetchone() != (state['input'],):
                raise ValueError('document contract changed during diagnosis')
            yield db
        finally:
            db.execute('RELEASE document_contract_read')


def contract_rows(root, state, kinds, files=None, cells=None):
    """Read requested row kinds and source owners; keep interpreted architecture in relational columns."""
    with contract_snapshot(root,state) as db:
        rid=state['root_id']
        marks=','.join('?' for _ in kinds)
        sql="SELECT r.id,d.path,r.line,r.kind FROM contract_documents c JOIN documents d ON d.id=c.document_id JOIN document_rows r ON r.document_id=d.id WHERE c.root_id=? AND r.kind IN ("+marks+")"
        args=[rid,*kinds]
        if files is not None:
            local={'scope','members','body','constants','changes','overview','behaviors'}
            if set(kinds) <= local:
                names=','.join('?' for _ in files) or 'NULL'
                sql += " AND (r.id IN (SELECT row_id FROM contract_targets WHERE file IN ("+names+")) OR r.id IN (SELECT row_id FROM contract_targets WHERE role='pattern')"
                args.extend(sorted(files))
                if 'behaviors' in kinds:
                    sql += " OR r.kind='behaviors' AND EXISTS(SELECT 1 FROM document_cells x WHERE x.row_id=r.id AND x.column_name='증거' AND x.value NOT IN ('','-'))"
                sql += ')'
            elif set(kinds) == {'architecture'}:
                names=','.join('?' for _ in files) or 'NULL'
                seed="SELECT a.node_key FROM contract_architecture a JOIN document_rows r ON r.id=a.row_id JOIN documents d ON d.id=r.document_id WHERE d.root_id=? AND (a.row_id IN (SELECT row_id FROM contract_targets WHERE file IN ("+names+"))"
                seed += ''.join(" OR ? LIKE a.folder || '/%'" for _ in files) + ')'
                sql = ("WITH RECURSIVE related(node) AS ("+seed+
                    " UNION SELECT a.owner_key FROM contract_architecture a JOIN related x ON x.node=a.node_key WHERE a.owner_key<>''"
                    " UNION SELECT e.target FROM contract_architecture_edges e JOIN related x ON x.node=e.source WHERE e.relation<>'owns'"
                    " UNION SELECT e.source FROM contract_architecture_edges e JOIN related x ON x.node=e.target WHERE e.relation<>'owns') "+sql+
                    " AND r.id IN (SELECT a.row_id FROM contract_architecture a JOIN related x ON x.node=a.node_key)")
                args=[rid,*sorted(files),*sorted(files),*args]
        for column,value in sorted((cells or {}).items()):
            sql += ' AND r.id IN (SELECT row_id FROM document_cells WHERE column_name=? AND value=?)'
            args.extend((column,value))
        sql += ' ORDER BY c.ordinal,r.ordinal'
        rows={row_id:dict(doc=doc,line=line,kind=kind,cells={},parsed={}) for row_id,doc,line,kind in db.execute(sql,args)}
        for start in range(0,len(rows),300):
            ids=list(rows)[start:start+300]; marks=','.join('?' for _ in ids)
            for row_id,col,value in db.execute('SELECT row_id,column_name,value FROM document_cells WHERE row_id IN ('+marks+')',ids):
                rows[row_id]['cells'][col]=value
            for row_id,sig,name,params,key,path,kind,has_kind in db.execute('SELECT * FROM document_members WHERE row_id IN ('+marks+')',ids):
                p=dict(signature=sig,name=name,params=params,key=key,path=path)
                if has_kind:p['kind']=kind
                rows[row_id]['parsed']=p
            for values in db.execute('SELECT * FROM contract_architecture WHERE row_id IN ('+marks+')',ids):
                row_id,node,owner,key,sig,*extra=values
                p=dict(nodeKey=node,ownerKey=owner,declarationKey=(key,sig) if sig is not None else key,edges=[],sourceLocations=[])
                p.update((k,v) for k,v in zip(('folder','memberFile','memberOwner','memberName','memberKind','signature','external','inputHash','moduleKey'),extra[:-1]) if v is not None)
                if extra[-1]:p['entryMembers']=[]
                if 'inputHash' in p:p['affectedFiles']=[]
                rows[row_id]['parsed']=p
            for table,key,cols in (('contract_architecture_edges','edges','source,relation,target,doc,line'),('contract_architecture_members','entryMembers','member_key,signature'),('contract_architecture_locations','sourceLocations','doc,line')):
                for row_id,*values in db.execute('SELECT row_id,'+cols+' FROM '+table+' WHERE row_id IN ('+marks+') ORDER BY row_id,ordinal',ids):
                    rows[row_id]['parsed'].setdefault(key,[]).append(tuple(values))
            for row_id,file in db.execute('SELECT row_id,file FROM contract_architecture_files WHERE row_id IN ('+marks+') ORDER BY file',ids):
                rows[row_id]['parsed'].setdefault('affectedFiles',[]).append(file)
        return list(rows.values())


def contract_text(root, state, path):
    """Fetch one requested document, with the same validated input identity."""
    with contract_snapshot(root,state) as db:
        row=db.execute("SELECT d.source FROM contract_documents c JOIN documents d ON d.id=c.document_id WHERE c.root_id=? AND d.path=?",(state['root_id'],path)).fetchone()
        if row is None: raise KeyError(path)
        return row[0].split('\n')


def directory(db, base, path):
    """Record real path parents independently of the semantic module hierarchy."""
    base = os.path.normcase(os.path.abspath(base))
    db.execute("INSERT OR IGNORE INTO workspace_roots(absolute_path) VALUES(?)", (base,))
    rid = db.execute("SELECT id FROM workspace_roots WHERE absolute_path=?", (base,)).fetchone()[0]
    parent = None
    parts = path.replace('\\', '/').strip('/').split('/') if path else []
    for n in range(len(parts) + 1):
        rel = '/'.join(parts[:n])
        got = db.execute("SELECT id FROM directories WHERE root_id=? AND path=?", (rid, rel)).fetchone()
        if got: parent = got[0]
        else:
            parent = db.execute("INSERT INTO directories(root_id,parent_id,name,path) VALUES(?,?,?,?)",
                                (rid, parent, parts[n-1] if n else '', rel)).lastrowid
    return rid, parent


def read_document(root, source_root, rel, stamp, parser):
    """Reconstruct rows from indexed columns without parsing unchanged Markdown."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        saved = db.execute("SELECT d.id,d.mtime,d.size,d.ctime,d.parser,d.source FROM documents d JOIN workspace_roots r ON r.id=d.root_id "
                           "WHERE r.absolute_path=? AND d.path=?", (os.path.normcase(os.path.abspath(source_root)), rel)).fetchone()
        if saved is None or saved[1:5] != (*stamp, parser): return None
        did, *_, text = saved
        part = dict(text=text.split('\n'),rows=[],issues=[])
        rows = {}; normalized = {}
        for row_id, ordinal, line, kind in db.execute("SELECT id,ordinal,line,kind FROM document_rows WHERE document_id=? ORDER BY ordinal", (did,)):
            row = dict(line=line,kind=kind,cells={},parsed={})
            rows[row_id] = (ordinal,row); part['rows'].append(row)
        for row_id, col, value in db.execute("SELECT c.row_id,c.column_name,c.value FROM document_cells c JOIN document_rows r ON r.id=c.row_id WHERE r.document_id=?", (did,)):
            rows[row_id][1]['cells'][col] = value
        for row_id,sig,name,params,key,path,kind,has_kind in db.execute("SELECT m.* FROM document_members m JOIN document_rows r ON r.id=m.row_id WHERE r.document_id=?", (did,)):
            row = rows[row_id][1]
            value = dict(signature=sig,name=name,params=params,key=key,path=path)
            if has_kind: value['kind'] = kind
            normalized[(row['line'],row['kind'])] = (value,[])
        for ordinal,row_ordinal,code,file,line,message in db.execute("SELECT ordinal,row_ordinal,code,file,line,message FROM document_parse_issues WHERE document_id=? ORDER BY ordinal", (did,)):
            issue = (code,file,line,message)
            if row_ordinal is None: part['issues'].append(issue)
            else:
                row = part['rows'][row_ordinal]
                normalized.setdefault((row['line'],row['kind']),({},[]))[1].append(issue)
        for diagram_id,row_id in db.execute("SELECT g.id,g.row_id FROM document_diagrams g JOIN document_rows r ON r.id=g.row_id WHERE r.document_id=?", (did,)):
            raw = tuple(db.execute("SELECT line,text FROM diagram_source_lines WHERE diagram_id=? ORDER BY ordinal", (diagram_id,)))
            rows[row_id][1]['parsed'] = dict(raw=raw,syntax={})
        return part,normalized


def reference_tokens(root, source_root, paths, updates=None):
    """Persist document reference occurrences as scalar rows owned by the source document."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        base = os.path.normcase(os.path.abspath(source_root))
        ids = {}
        paths = list(paths)
        for start in range(0,len(paths),400):
            selected = paths[start:start+400]
            marks = ','.join('?' for _ in selected)
            ids.update(db.execute("SELECT d.path,d.id FROM documents d JOIN workspace_roots r ON r.id=d.root_id WHERE r.absolute_path=? AND d.path IN ("+marks+")", (base,*selected)))
        if updates is not None:
            with db:
                for path,tokens in updates.items():
                    if path not in ids: continue
                    did = ids[path]
                    db.execute("DELETE FROM document_reference_inputs WHERE document_id=?", (did,))
                    db.execute("INSERT INTO document_reference_inputs VALUES(?)", (did,))
                    values = [(line,'rule','',rule) for line,rules,_ in tokens for rule in rules]
                    values += [(line,'member',owner,name) for line,_,members in tokens for owner,name in members]
                    db.executemany("INSERT INTO document_references VALUES(?,?,?,?,?,?)", ((did,i,*row) for i,row in enumerate(values)))
            return
        results = {}
        owners = {did:path for path,did in ids.items()}
        values = list(owners)
        for start in range(0,len(values),400):
            selected = values[start:start+400]
            marks = ','.join('?' for _ in selected)
            for did, in db.execute("SELECT document_id FROM document_reference_inputs WHERE document_id IN ("+marks+")", selected):
                results[owners[did]] = {}
            for did,line,kind,owner,name in db.execute("SELECT document_id,line,kind,owner,name FROM document_references WHERE document_id IN ("+marks+") ORDER BY document_id,ordinal", selected):
                pair = results[owners[did]].setdefault(line,([],[]))
                if kind == 'rule': pair[0].append(name)
                else: pair[1].append((owner,name))
        return {path:[(line,tuple(rules),tuple(members)) for line,(rules,members) in sorted(lines.items())] for path,lines in results.items()}


def read_documents(root, source_root, requests):
    """Read unchanged documents in bounded SQL batches, preserving per-document rows."""
    if not requests:
        return {}
    with ledger._TABLE_LOCK:
        db = connection(root)
        source = os.path.normcase(os.path.abspath(source_root))
        found = {}
        for start in range(0, len(requests), 400):
            names = list(requests)[start:start + 400]
            marks = ','.join('?' for _ in names)
            for did,rel,mtime,size,ctime,parser,text in db.execute(
                    'SELECT d.id,d.path,d.mtime,d.size,d.ctime,d.parser,d.source FROM documents d '
                    'JOIN workspace_roots r ON r.id=d.root_id WHERE r.absolute_path=? AND d.path IN (' + marks + ')',
                    (source,*names)):
                if (mtime,size,ctime,parser) == (*requests[rel][0],requests[rel][1]):
                    found[did] = (rel,dict(text=text.split('\n'),rows=[],issues=[]),{})
        if not found:
            return {}
        rows = {}
        diagrams = {}
        for start in range(0,len(found),400):
            ids = list(found)[start:start + 400]
            marks = ','.join('?' for _ in ids)
            for row_id,did,ordinal,line,kind in db.execute(
                    'SELECT id,document_id,ordinal,line,kind FROM document_rows WHERE document_id IN ('+marks+') '
                    'ORDER BY document_id,ordinal',ids):
                row = dict(line=line,kind=kind,cells={},parsed={})
                found[did][1]['rows'].append(row)
                rows[row_id] = (did,row)
            for row_id,col,value in db.execute(
                    'SELECT c.row_id,c.column_name,c.value FROM document_cells c JOIN document_rows r ON r.id=c.row_id '
                    'WHERE r.document_id IN ('+marks+')',ids):
                rows[row_id][1]['cells'][col] = value
            for row_id,sig,name,params,key,path,kind,has_kind in db.execute(
                    'SELECT m.* FROM document_members m JOIN document_rows r ON r.id=m.row_id '
                    'WHERE r.document_id IN ('+marks+')',ids):
                did,row = rows[row_id]
                value = dict(signature=sig,name=name,params=params,key=key,path=path)
                if has_kind: value['kind'] = kind
                found[did][2][(row['line'],row['kind'])] = (value,[])
            for did,row_ordinal,code,file,line,message in db.execute(
                    'SELECT document_id,row_ordinal,code,file,line,message FROM document_parse_issues '
                    'WHERE document_id IN ('+marks+') ORDER BY document_id,ordinal',ids):
                part,normalized = found[did][1:]
                issue = (code,file,line,message)
                if row_ordinal is None:
                    part['issues'].append(issue)
                else:
                    row = part['rows'][row_ordinal]
                    normalized.setdefault((row['line'],row['kind']),({},[]))[1].append(issue)
            for diagram_id,row_id in db.execute(
                    'SELECT g.id,g.row_id FROM document_diagrams g JOIN document_rows r ON r.id=g.row_id '
                    'WHERE r.document_id IN ('+marks+')',ids):
                diagrams[diagram_id] = rows[row_id][1]
        if diagrams:
            for start in range(0,len(diagrams),400):
                ids = list(diagrams)[start:start + 400]
                marks = ','.join('?' for _ in ids)
                raw = {}
                for diagram_id,line,text in db.execute(
                        'SELECT diagram_id,line,text FROM diagram_source_lines WHERE diagram_id IN ('+marks+') '
                        'ORDER BY diagram_id,ordinal',ids):
                    raw.setdefault(diagram_id,[]).append((line,text))
                for diagram_id in ids:
                    diagrams[diagram_id]['parsed'] = dict(raw=tuple(raw.get(diagram_id,())),syntax={})
        return {rel:(part,normalized) for rel,part,normalized in found.values()}


def write_document(root, source_root, rel, stamp, parser, part, normalized):
    """Replace only changed document rows, keeping source cells separately from interpreted members."""
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            rid,directory_id = directory(db,source_root,os.path.dirname(rel))
            old = db.execute("SELECT id FROM documents WHERE root_id=? AND path=?",(rid,rel)).fetchone()
            old_cells = {} if old is None else {(line,kind,col):value for line,kind,col,value in db.execute(
                "SELECT r.line,r.kind,c.column_name,c.value FROM document_rows r JOIN document_cells c ON c.row_id=r.id WHERE document_id=?",old)}
            if old:
                did = old[0]
                db.execute("DELETE FROM document_reference_inputs WHERE document_id=?", (did,))
                db.execute("DELETE FROM document_rows WHERE document_id=?",(did,))
                db.execute("DELETE FROM document_parse_issues WHERE document_id=?",(did,))
                db.execute("UPDATE documents SET directory_id=?,mtime=?,size=?,ctime=?,parser=?,source=? WHERE id=?",
                           (directory_id,*stamp,parser,'\n'.join(part.texts[rel]),did))
            else:
                did = db.execute("INSERT INTO documents(root_id,directory_id,name,path,mtime,size,ctime,parser,source) VALUES(?,?,?,?,?,?,?,?,?)",
                    (rid,directory_id,os.path.basename(rel),rel,*stamp,parser,'\n'.join(part.texts[rel]))).lastrowid
            new_cells = {}
            issues = [(i,None,x) for i,x in enumerate(part.issues)]
            for ordinal,row in enumerate(part.rows):
                row_id = db.execute("INSERT INTO document_rows(document_id,ordinal,line,kind) VALUES(?,?,?,?)",(did,ordinal,row.line,row.kind)).lastrowid
                db.executemany("INSERT INTO document_cells VALUES(?,?,?)",((row_id,k,v) for k,v in row.cells.items()))
                new_cells.update(((row.line,row.kind,k),v) for k,v in row.cells.items())
                got = normalized.get((row.line,row.kind))
                if got:
                    value,errors = got
                    if value:
                        db.execute("INSERT INTO document_members VALUES(?,?,?,?,?,?,?,?)",(row_id,*(value.get(k) for k in ('signature','name','params','key','path','kind')),int('kind' in value)))
                    issues.extend((len(issues)+i,ordinal,error) for i,error in enumerate(errors))
                if row.kind == 'architecture-graph':
                    raw = row.parsed['raw']; digest = hashlib.sha256('\n'.join(t for _,t in raw).encode()).hexdigest()
                    graph_id = db.execute("INSERT INTO document_diagrams(row_id,local_key,diagram_type,source_hash) VALUES(?,?,?,?)",(row_id,row.cells['도식 ID'],'flowchart',digest)).lastrowid
                    db.executemany("INSERT INTO diagram_source_lines VALUES(?,?,?,?)",((graph_id,i,no,text) for i,(no,text) in enumerate(raw)))
            db.executemany("INSERT INTO document_parse_issues(document_id,ordinal,row_ordinal,code,file,line,message) VALUES(?,?,?,?,?,?,?)",
                           ((did,i,owner,x.code,x.file,x.line,x.message) for i,owner,x in issues))
            for key in old_cells.keys() | new_cells.keys():
                if old_cells.get(key)!=new_cells.get(key):
                    db.execute("INSERT INTO design_changes(document_path,line,operation,field,old_value,new_value,changed_at) VALUES(?,?,?,?,?,?,?)",
                        (rel,key[0],'insert' if key not in old_cells else 'delete' if key not in new_cells else 'update',key[2],old_cells.get(key),new_cells.get(key),ledger.now()))


def publish(root, ds, cur, source_records, only_files=None):
    """Join split documents, actual folders and current declarations using explicit design IDs."""
    if not hasattr(ds,"source_root"): return
    with ledger._TABLE_LOCK:
        db = connection(root)
        with db:
            rid,_ = directory(db,ds.source_root,'')
            # Only the current source's declaration rows change. Declaration identity
            # is independent of the graph's transient integer indexes.
            code_root,_ = directory(db,root,'')
            if only_files is None:
                code_files = {path:(fid,inp) for fid,path,inp in db.execute("SELECT id,path,input FROM code_files WHERE root_id=?",(code_root,))}
                live = {path for path in cur if path.endswith(('.py','.cs'))}
            else:
                only_files = set(only_files)
                code_files = {path:(fid,inp) for selected in sorted(only_files) for fid,path,inp in db.execute(
                    "SELECT id,path,input FROM code_files WHERE root_id=? AND path=?",(code_root,selected))}
                live = {path for path in only_files if path in cur and path.endswith(('.py','.cs'))}
            indexed = isinstance(cur, ledger.SourceIndex)
            selected = (cur.summaries() if indexed else cur.items()) if only_files is None else (
                (path, dict.__getitem__(cur, path) if indexed else cur[path]) for path in only_files if path in cur)
            for path,entry in selected:
                if not path.endswith(('.py','.cs')): continue
                live.add(path)
                inp = entry.get('sha256','') + ':' + str(entry.get('parser')) + ':' + str(entry.get('unit'))
                prior = code_files.get(path)
                if prior and prior[1]==inp: continue
                entry = cur[path]
                _,directory_id = directory(db,root,os.path.dirname(path))
                if prior:
                    fid = prior[0]
                    db.execute("UPDATE code_files SET directory_id=?,input=? WHERE id=?",(directory_id,inp,fid))
                else:
                    fid = db.execute("INSERT INTO code_files(root_id,directory_id,path,input) VALUES(?,?,?,?)",(code_root,directory_id,path,inp)).lastrowid
                old = {key:(node_id,owner_path,name,kind,signature,line)
                       for key,node_id,owner_path,name,kind,signature,line in db.execute(
                           "SELECT stable_key,id,owner_path,name,kind,signature,line FROM code_nodes WHERE file_id=?",(fid,))}
                keys = set()
                for symbol,_,key,_ in source_records(path,entry):
                    keys.add(key)
                    args = (fid,key,symbol['path'],symbol['name'],symbol['kind'],symbol['signature'],symbol['line'])
                    if key in old and old[key][1:] == args[2:]:
                        continue
                    db.execute("INSERT INTO code_nodes(file_id,stable_key,owner_path,name,kind,signature,line) VALUES(?,?,?,?,?,?,?) "
                               "ON CONFLICT(file_id,stable_key) DO UPDATE SET owner_path=excluded.owner_path,name=excluded.name,kind=excluded.kind,signature=excluded.signature,line=excluded.line",args)
                db.executemany("DELETE FROM code_nodes WHERE id=?",((old[key][0],) for key in old.keys()-keys))
            db.executemany("DELETE FROM code_files WHERE id=?",((code_files[path][0],) for path in code_files.keys()-live))
            if only_files is not None:
                # Document/module/diagram relationships already exist. Resolve only
                # expectations targeting changed code; deletion cascades remove old links.
                for path in sorted(live):
                    wanted = set(db.execute(
                        "SELECT DISTINCT e.entity_id,n.id,'implements' FROM link_expectations e "
                        "JOIN code_files f ON f.root_id=? AND f.path=e.target_file "
                        "JOIN code_nodes n ON n.file_id=f.id AND n.owner_path=e.target_owner "
                        "AND n.name=e.target_name AND n.kind=e.target_kind AND n.signature=e.signature "
                        "JOIN design_entities d ON d.id=e.entity_id AND d.root_id=? WHERE e.target_file=?",
                        (code_root,rid,path)))
                    existing = set(db.execute(
                        "SELECT l.entity_id,l.code_node_id,l.relation_kind FROM code_files f "
                        "JOIN code_nodes n ON n.file_id=f.id JOIN design_code_links l ON l.code_node_id=n.id "
                        "JOIN design_entities d ON d.id=l.entity_id AND d.root_id=? WHERE f.root_id=? AND f.path=?",
                        (rid,code_root,path)))
                    db.executemany("DELETE FROM design_code_links WHERE entity_id=? AND code_node_id=? AND relation_kind=?",existing-wanted)
                    db.executemany("INSERT INTO design_code_links VALUES(?,?,?)",wanted-existing)
                return
            documents = {path:(did,directory_id) for did,directory_id,path in db.execute(
                "SELECT id,directory_id,path FROM documents WHERE root_id=?",(rid,))}
            for path in documents.keys() - set(ds.docs):
                db.execute("DELETE FROM documents WHERE id=?",(documents[path][0],))
            documents = {path:value for path,value in documents.items() if path in ds.docs}
            row_ids = {(path,line,kind):row_id for path,line,kind,row_id in db.execute(
                "SELECT d.path,r.line,r.kind,r.id FROM documents d JOIN document_rows r ON r.document_id=d.id WHERE d.root_id=?",(rid,))}
            graph_ids = {}
            for graph in ds.of('architecture-graph'):
                row_id = row_ids.get((graph.doc,graph.line,graph.kind))
                if row_id is None: continue
                got = db.execute("SELECT id,semantic_hash FROM document_diagrams WHERE row_id=?",(row_id,)).fetchone()
                if got is None: continue
                gid,previous = got
                graph_ids[(graph.doc,graph.cells['도식 ID'])] = gid
                syntax = graph.parsed['syntax']
                # Stable scalar tuples are hashed for invalidation only; SQL stores
                # each node/edge/group separately, never this hash input as a payload.
                facts = (sorted(syntax['nodes'].items()),sorted(syntax.get('labels',{}).items()),
                         syntax['edges'],sorted(syntax['refs'].items()),sorted(syntax.get('groups',{}).items()),syntax.get('group_members',()))
                digest = hashlib.sha256(repr(facts).encode()).hexdigest()
                if previous==digest: continue
                db.execute("DELETE FROM diagram_nodes WHERE diagram_id=?",(gid,))
                db.execute("DELETE FROM diagram_groups WHERE diagram_id=?",(gid,))
                groups = {}
                for key,(parent,label,line) in syntax.get('groups',{}).items():
                    groups[key] = db.execute("INSERT INTO diagram_groups(diagram_id,parent_id,local_key,label,line) VALUES(?,?,?,?,?)",
                        (gid,groups.get(parent),key,label,line)).lastrowid
                nodes = {}
                for key,line in syntax['nodes'].items():
                    nodes[key] = db.execute("INSERT INTO diagram_nodes(diagram_id,local_key,label,line) VALUES(?,?,?,?)",
                        (gid,key,syntax.get('labels',{}).get(key,key),line)).lastrowid
                db.executemany("INSERT OR IGNORE INTO diagram_group_members VALUES(?,?)",
                    ((groups[g],nodes[n]) for g,n in syntax.get('group_members',()) if g in groups and n in nodes))
                db.executemany("INSERT INTO diagram_edges(diagram_id,source_id,target_id,relation_kind,line) VALUES(?,?,?,?,?)",
                    ((gid,nodes[a],nodes[b],kind,line) for a,kind,b,line in syntax['edges'] if a in nodes and b in nodes))
                db.executemany("INSERT INTO diagram_aliases(node_id,target_diagram,target_node) VALUES(?,?,?)",
                    ((nodes[name],target,node) for name,(target,node,_) in syntax['refs'].items() if name in nodes))
                db.execute("UPDATE document_diagrams SET semantic_hash=? WHERE id=?",(digest,gid))
            addresses = {path+'#'+graph+'/'+key:node for path,graph,key,node in db.execute(
                "SELECT d.path,g.local_key,n.local_key,n.id FROM documents d JOIN document_rows r ON r.document_id=d.id "
                "JOIN document_diagrams g ON g.row_id=r.id JOIN diagram_nodes n ON n.diagram_id=g.id WHERE d.root_id=?",(rid,))}
            for address,node_id in addresses.items():
                target=getattr(ds,'architecture',{}).get('resolved',{}).get(address)
                target_id=addresses.get(target)
                db.execute("UPDATE diagram_aliases SET resolved_node_id=? WHERE node_id=? AND resolved_node_id IS NOT ?",(target_id,node_id,target_id))
            declared = {r.parsed['nodeKey']:r for r in ds.of('architecture')}
            resolved = getattr(ds,'architecture',{}).get('resolved',{})
            entities = {key:eid for key,eid in db.execute("SELECT stable_key,id FROM design_entities WHERE root_id=?",(rid,))}
            live_entities = set()
            for key,row in declared.items():
                if resolved.get(key,key)!=key: continue
                live_entities.add(key)
                kind,name = row.cells['종류'],row.cells['구조 ID']
                db.execute("INSERT INTO design_entities(root_id,stable_key,kind,name) VALUES(?,?,?,?) "
                    "ON CONFLICT(root_id,stable_key) DO UPDATE SET kind=excluded.kind,name=excluded.name WHERE kind<>excluded.kind OR name<>excluded.name",(rid,key,kind,name))
                entities[key] = db.execute("SELECT id FROM design_entities WHERE root_id=? AND stable_key=?",(rid,key)).fetchone()[0]
                if kind=='module': db.execute("INSERT OR IGNORE INTO modules(entity_id) VALUES(?)",(entities[key],))
            for key in live_entities:
                row=declared[key]; parent=entities.get(row.parsed.get('ownerKey'))
                if row.cells['종류']=='module':
                    owner=declared.get(row.parsed.get('ownerKey'))
                    module_parent=entities.get(owner.parsed.get('moduleKey')) if owner else None
                    db.execute("UPDATE modules SET parent_module_id=? WHERE entity_id=? AND parent_module_id IS NOT ?",(module_parent,entities[key],module_parent))
                db.execute("UPDATE design_entities SET parent_id=? WHERE id=? AND parent_id IS NOT ?",(parent,entities[key],parent))
            wanted = {name:set() for name in ('module_code_directories','module_spec_directories','document_assignments',
                'document_entity_sections','diagram_entity_links','diagram_directory_links','diagram_module_links','module_dependencies','design_code_links','link_expectations')}
            codes = {}
            for node,path,owner,name,kind,signature in db.execute("SELECT n.id,f.path,n.owner_path,n.name,n.kind,n.signature FROM code_nodes n JOIN code_files f ON f.id=n.file_id WHERE f.root_id=?",(code_root,)):
                codes.setdefault((path,owner,name,kind,signature),[]).append(node)
            for key,row in declared.items():
                canonical=resolved.get(key,key); eid=entities.get(canonical)
                row_id=row_ids.get((row.doc,row.line,row.kind))
                if not eid or row_id is None: continue
                wanted['document_entity_sections'].add((row_id,eid,'reference' if canonical!=key else 'definition'))
                node_id=addresses.get(key)
                if node_id: wanted['diagram_entity_links'].add((node_id,eid))
                definition=declared.get(canonical,row); p=definition.parsed
                module_id=entities.get(p.get('moduleKey'))
                if module_id:
                    for doc,_ in p.get('sourceLocations',[(row.doc,row.line)]):
                        if doc not in documents: continue
                        did,directory_id=documents[doc]
                        role='structure' if doc==row.doc else 'interface' if definition.cells['종류']=='interface' else 'class' if definition.cells['종류']=='class' else 'method'
                        wanted['document_assignments'].add((did,module_id,role))
                        wanted['module_spec_directories'].add((module_id,directory_id))
                    if node_id: wanted['diagram_module_links'].add((node_id,module_id))
                if definition.cells['종류']=='module' and p.get('folder'):
                    _,directory_id=directory(db,root,p['folder'])
                    wanted['module_code_directories'].add((eid,directory_id,1))
                    if node_id: wanted['diagram_directory_links'].add((node_id,directory_id))
                target=(p.get('memberFile'),p.get('memberOwner'),p.get('memberName'),p.get('memberKind'),p.get('signature'))
                wanted['link_expectations'].add((row_id,eid,definition.cells['선언 연결'],*target))
                for code in codes.get(target,()): wanted['design_code_links'].add((eid,code,'implements'))
            for a,kind,b,_,_ in getattr(ds,'architecture',{}).get('edges',()):
                ma=entities.get(declared[a].parsed.get('moduleKey')); mb=entities.get(declared[b].parsed.get('moduleKey'))
                if ma and mb and ma!=mb: wanted['module_dependencies'].add((ma,mb,kind))
            # All relationships are diffed; no wholesale delete/reinsert on restart.
            for table,rows in wanted.items():
                columns=[c[1] for c in db.execute('PRAGMA table_info("'+table+'")')]
                if table=='document_assignments': owner='module_id'
                elif table in ('module_code_directories','module_spec_directories'): owner='module_id'
                elif table=='module_dependencies': owner='source_id'
                else: owner='entity_id' if 'entity_id' in columns else 'module_id' if 'module_id' in columns else None
                if owner:
                    existing=set(db.execute('SELECT * FROM "'+table+'" WHERE "'+owner+'" IN (SELECT id FROM design_entities WHERE root_id=?)',(rid,)))
                else:
                    existing=set(db.execute('SELECT * FROM "'+table+'" WHERE node_id IN (SELECT n.id FROM diagram_nodes n JOIN document_diagrams g ON g.id=n.diagram_id JOIN document_rows r ON r.id=g.row_id JOIN documents d ON d.id=r.document_id WHERE d.root_id=?)',(rid,)))
                where=' AND '.join('"'+c+'" IS ?' for c in columns)
                db.executemany('DELETE FROM "'+table+'" WHERE '+where,existing-rows)
                db.executemany('INSERT INTO "'+table+'" VALUES('+','.join('?' for _ in columns)+')',rows-existing)
            # Remove old entities only after dropping their links and ownership.
            removed=[entities[key] for key in entities.keys()-live_entities]
            for eid in removed:
                db.execute("UPDATE design_entities SET parent_id=NULL WHERE parent_id=?",(eid,))
                db.execute("UPDATE modules SET parent_module_id=NULL WHERE parent_module_id=?",(eid,))
                db.execute("DELETE FROM design_entities WHERE id=?",(eid,))

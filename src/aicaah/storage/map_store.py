"""Typed SQL persistence for the code map; no graph analysis or UI rendering."""
import hashlib
import contextlib
import os
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from storage import diff as diffmod
from storage import ledger
from parsing import cache as cachemod

_MAP_REL = ".spec-conformance/Cache/map/current.row"
_MAP_TABLES = """
CREATE TABLE IF NOT EXISTS map_head(id INTEGER PRIMARY KEY CHECK(id=1), rev INTEGER NOT NULL, stamp TEXT NOT NULL, structure_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS map_layers(ord INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS map_modules(ord INTEGER PRIMARY KEY, folder TEXT NOT NULL, layer INTEGER NOT NULL REFERENCES map_layers(ord));
CREATE TABLE IF NOT EXISTS map_files(ord INTEGER PRIMARY KEY, path TEXT NOT NULL, module INTEGER NOT NULL REFERENCES map_modules(ord));
CREATE TABLE IF NOT EXISTS map_decls(ord INTEGER PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, file INTEGER NOT NULL REFERENCES map_files(ord), line INTEGER NOT NULL, end INTEGER NOT NULL, container INTEGER NOT NULL, access TEXT NOT NULL, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS map_edges(ord INTEGER PRIMARY KEY, source INTEGER NOT NULL REFERENCES map_decls(ord), target INTEGER NOT NULL REFERENCES map_decls(ord), writing INTEGER NOT NULL, bad INTEGER NOT NULL, bypass INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS map_signatures(decl INTEGER PRIMARY KEY REFERENCES map_decls(ord), signature TEXT NOT NULL, type TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS map_bases(decl INTEGER NOT NULL REFERENCES map_decls(ord), kind TEXT NOT NULL, ord INTEGER NOT NULL, internal INTEGER, external TEXT, PRIMARY KEY(decl,kind,ord));
CREATE TABLE IF NOT EXISTS map_variables(decl INTEGER NOT NULL REFERENCES map_decls(ord), ord INTEGER NOT NULL, name TEXT, kind TEXT, scope TEXT, line INTEGER, end INTEGER, has_end INTEGER NOT NULL, PRIMARY KEY(decl,ord));
CREATE TABLE IF NOT EXISTS map_modifiers(decl INTEGER NOT NULL REFERENCES map_decls(ord), ord INTEGER NOT NULL, name TEXT NOT NULL, PRIMARY KEY(decl,ord));
CREATE TABLE IF NOT EXISTS map_folders(path TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS map_folder_counts(path TEXT NOT NULL REFERENCES map_folders(path), kind TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(path,kind));
CREATE TABLE IF NOT EXISTS map_findings(ord INTEGER PRIMARY KEY, code TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL, message TEXT NOT NULL, rule TEXT NOT NULL, decl INTEGER NOT NULL, map_file INTEGER NOT NULL, first_seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS map_snippets(file TEXT NOT NULL,line INTEGER NOT NULL,input TEXT NOT NULL,snippet TEXT NOT NULL,PRIMARY KEY(file,line));
CREATE INDEX IF NOT EXISTS map_file_path ON map_files(path);
CREATE INDEX IF NOT EXISTS map_decl_file ON map_decls(file);
CREATE INDEX IF NOT EXISTS map_edge_source ON map_edges(source);
CREATE INDEX IF NOT EXISTS map_edge_target ON map_edges(target);
CREATE TABLE IF NOT EXISTS map_work(rev INTEGER PRIMARY KEY,commit_id INTEGER NOT NULL,body INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS map_work_files(rev INTEGER REFERENCES map_work(rev) ON DELETE CASCADE,file TEXT,layer TEXT,PRIMARY KEY(rev,file));
CREATE TABLE IF NOT EXISTS map_work_layers(rev INTEGER REFERENCES map_work(rev) ON DELETE CASCADE,ord INTEGER,name TEXT,PRIMARY KEY(rev,ord));
CREATE TABLE IF NOT EXISTS map_work_moves(rev INTEGER REFERENCES map_work(rev) ON DELETE CASCADE,file TEXT,ord INTEGER,a INTEGER,b INTEGER,c INTEGER,d INTEGER,PRIMARY KEY(rev,file,ord));
CREATE TABLE IF NOT EXISTS map_work_folders(rev INTEGER REFERENCES map_work(rev) ON DELETE CASCADE,path TEXT,PRIMARY KEY(rev,path));
CREATE TABLE IF NOT EXISTS map_work_counts(rev INTEGER REFERENCES map_work(rev) ON DELETE CASCADE,path TEXT,kind TEXT,count INTEGER,PRIMARY KEY(rev,path,kind));
CREATE TABLE IF NOT EXISTS map_projection(id INTEGER PRIMARY KEY CHECK(id=1),rev INTEGER NOT NULL);
"""


def publish_sql(root, map_data, findings, previous=None, source_snippets=None):
    """Publish typed map relationships and current findings, changing only differing rows."""
    structural = ("layers", "mods", "files", "decls", "edges", "sig", "bases", "variables", "modifiers", "folders")
    digest = cachemod.POLICY.key('publication-map',tuple(map_data[key] for key in structural))
    with ledger._TABLE_LOCK:
        db = ledger.table_connection(root, _MAP_REL, True)
        for sql in _MAP_TABLES.split(";"):
            if sql.strip(): db.execute(sql)
        old = db.execute("SELECT structure_hash,rev,stamp FROM map_head WHERE id=1").fetchone()
        db.execute("SAVEPOINT map_publication")
        try:
            if old is None or old[0] != digest:
                def records(data):
                    return {
                        "map_layers": [(i, value) for i, value in enumerate(data["layers"])],
                        "map_modules": [(i, *row) for i, row in enumerate(data["mods"])],
                        "map_files": [(i, *row) for i, row in enumerate(data["files"])],
                        "map_decls": [(i, *row) for i, row in enumerate(data["decls"])],
                        "map_edges": [(i, *row) for i, row in enumerate(data["edges"])],
                        "map_signatures": [(i, *row) for i, row in enumerate(data["sig"])],
                        "map_bases": [(i, kind, j, value if kind == "internal" else None,
                                       value if kind == "external" else None)
                                      for i, pair in enumerate(data["bases"]) if pair
                                      for kind, values in zip(("internal", "external"), pair)
                                      for j, value in enumerate(values)],
                        "map_variables": [(i, j, value.get("name"), value.get("kind"), value.get("scope"),
                                           value.get("line"), value.get("end"), int("end" in value))
                                          for i, items in enumerate(data["variables"]) for j, value in enumerate(items)],
                        "map_modifiers": [(i, j, name) for i, items in enumerate(data["modifiers"]) for j, name in enumerate(items)],
                        "map_folders": [(path,) for path in data["folders"]],
                        "map_folder_counts": [(path, kind, count) for path, values in data["folders"].items() for kind, count in values.items()]
                    }
                keys = {"map_bases": ("decl", "kind", "ord"), "map_variables": ("decl", "ord"),
                        "map_modifiers": ("decl", "ord"), "map_folders": ("path",),
                        "map_folder_counts": ("path", "kind"), "map_signatures": ("decl",)}
                for variables in map_data["variables"]:
                    if any(set(value) - {"name", "kind", "scope", "line", "end"} for value in variables):
                        raise ValueError("unknown map variable columns")
                target = records(map_data)
                retained = records(previous) if previous is not None and old and (
                    old[1], old[2]) == (previous.get("rev"), previous.get("stamp")) else None
                # A declaration ordinal can move across parents during an insertion.
                # Validate foreign keys at the atomic publication boundary.
                db.execute("PRAGMA defer_foreign_keys=ON")
                for table, rows in target.items():
                    columns = keys.get(table, ("ord",))
                    count = len(columns)
                    before = {tuple(row[:count]): tuple(row) for row in
                              (retained[table] if retained is not None else db.execute("SELECT * FROM " + table))}
                    after = {tuple(row[:count]): tuple(row) for row in rows}
                    where = " AND ".join(column + "=?" for column in columns)
                    db.executemany("DELETE FROM " + table + " WHERE " + where, before.keys() - after.keys())
                    for key, row in after.items():
                        if before.get(key) == row:
                            continue
                        if key in before:
                            # Fixed column names come from this module's schema, never source input.
                            names = [column[1] for column in db.execute("PRAGMA table_info(" + table + ")")][count:]
                            db.execute("UPDATE " + table + " SET " + ",".join(name + "=?" for name in names) +
                                       " WHERE " + where, row[count:] + key)
                        else:
                            db.execute("INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in row) + ")", row)
            current = [(i,f.code,f.file,f.line,f.message,f.rule,*map_data["finds"][i][4:])
                       for i,f in enumerate(findings)]
            previous = {row[0]:row for row in db.execute("SELECT ord,code,file,line,message,rule,decl,map_file,first_seen FROM map_findings")}
            db.executemany("DELETE FROM map_findings WHERE ord=?", ((i,) for i in previous if i >= len(current)))
            for row in current:
                if row != previous.get(row[0]):
                    db.execute("INSERT INTO map_findings VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(ord) DO UPDATE SET "
                               "code=excluded.code,file=excluded.file,line=excluded.line,message=excluded.message,"
                               "rule=excluded.rule,decl=excluded.decl,map_file=excluded.map_file,first_seen=excluded.first_seen", row)
            db.execute("INSERT INTO map_head VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                       "rev=excluded.rev,stamp=excluded.stamp,structure_hash=excluded.structure_hash",
                       (map_data["rev"],map_data["stamp"],digest))
            db.execute("INSERT OR REPLACE INTO map_projection VALUES(1,?)", (map_data["rev"],))
            db.execute("DELETE FROM map_work WHERE rev<=?", (map_data["rev"],))
            if source_snippets is not None:
                retained = {(file,line):(fingerprint,text) for file,line,fingerprint,text in db.execute("SELECT * FROM map_snippets")}
                desired = {(file,line):(fingerprint,text) for file,(fingerprint,lines) in source_snippets.items() for line,text in lines.items()}
                db.executemany("DELETE FROM map_snippets WHERE file=? AND line=?",retained.keys()-desired.keys())
                db.executemany("INSERT INTO map_snippets VALUES(?,?,?,?) ON CONFLICT(file,line) DO UPDATE SET input=excluded.input,snippet=excluded.snippet",
                    ((*key,*value) for key,value in desired.items() if retained.get(key)!=value))
            db.execute("RELEASE map_publication")
        except BaseException:
            db.execute("ROLLBACK TO map_publication")
            db.execute("RELEASE map_publication")
            raise


@contextlib.contextmanager
def _read_connection(root, relative):
    """A UI reader owns its WAL snapshot and never takes the diagnostic connection lock."""
    base,_=ledger.table_location(root,relative)
    path=os.path.join(base,'metadata.sqlite')
    if not os.path.isfile(path):
        yield None
        return
    with contextlib.closing(sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True)) as db:
        db.execute('BEGIN')
        yield db


def load_sql(root, rev, cur, structure=True):
    """Build the current code map from SQL rows without reconstructing a reference graph."""
    with _read_connection(root, _MAP_REL) as db:
        if db is None: return None
        head = db.execute("SELECT rev,stamp FROM map_head WHERE id=1").fetchone()
        if head is None or head[0] != rev: return None
        findings = db.execute("SELECT code,file,line,message,rule FROM map_findings ORDER BY file,line,code,message,rule").fetchall()
        snippets = {}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='map_snippets'").fetchone():
            for file,line,fingerprint,text in db.execute("SELECT file,line,input,snippet FROM map_snippets"):
                snippets.setdefault(file,(fingerprint,{}))[1][line] = text
        if not structure:
            projected=db.execute('SELECT rev FROM map_projection WHERE id=1').fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE name='map_projection'").fetchone() else head
            return dict(rev=head[0],stamp=head[1],projectionRev=projected[0] if projected else None,sourceSnippets=snippets),findings
        rows = lambda table, columns: db.execute("SELECT " + columns + " FROM " + table + " ORDER BY ord").fetchall()
        file_ids={old:i for i,(old,) in enumerate(rows('map_files','ord'))}
        mod_ids={old:i for i,(old,) in enumerate(rows('map_modules','ord'))}
        decl_ids={old:i for i,(old,) in enumerate(rows('map_decls','ord'))}
        sources = None
        if isinstance(cur,ledger.SourceIndex):
            # The map consumes file/count/error only. Reading all declaration
            # bodies here defeated scoped restart before analysis even started.
            with _read_connection(root,ledger.FILE_ROWS + '/index.row') as source_db:
                counts = dict(source_db.execute("SELECT record_file,count(*) FROM source_declarations GROUP BY record_file"))
            sources = [{"file":file,"symbolCount":counts.get(ledger.table_location(root,cur.rows[file])[1],0),
                        "error":dict.__getitem__(cur,file).get("error","")} for file in sorted(cur)]
        out = {"rev":head[0], "stamp":head[1],
               "layers":[r[0] for r in rows("map_layers","name")],
               "mods":[list(r) for r in rows("map_modules","folder,layer")],
               "files":[[p,mod_ids[m]] for p,m in rows("map_files","path,module")],
               "decls":[[n,k,file_ids[f],a,b,decl_ids.get(c,-1),v,s] for n,k,f,a,b,c,v,s in rows("map_decls","name,kind,file,line,end,container,access,status")],
               "edges":[[decl_ids[a],decl_ids[b],w,bad,decl_ids.get(bp,bp)] for a,b,w,bad,bp in rows("map_edges","source,target,writing,bad,bypass")],
               "sig":[list(r) for r in db.execute("SELECT signature,type FROM map_signatures ORDER BY decl")],
               "bases":[], "variables":[], "modifiers":[], "folders":{},
               "sourceFiles":sources if sources is not None else [{"file":rel,"symbolCount":len(entry.get("symbols") or []),"error":entry.get("error","")}
                              for rel,entry in sorted(cur.items())]}
        inner, outer = {}, {}
        for decl,kind,_,target,name in db.execute("SELECT decl,kind,ord,internal,external FROM map_bases ORDER BY decl,kind,ord"):
            (inner if kind == "internal" else outer).setdefault(decl_ids[decl],[]).append(decl_ids[target] if kind == "internal" else name)
        variables, modifiers = {}, {}
        for decl,_,name,kind,scope,line,end,has_end in db.execute(
                "SELECT decl,ord,name,kind,scope,line,end,has_end FROM map_variables ORDER BY decl,ord"):
            item={key:value for key,value in (("name",name),("kind",kind),("scope",scope),("line",line)) if value is not None}
            if has_end: item["end"] = end
            variables.setdefault(decl_ids[decl],[]).append(item)
        for decl,_,name in db.execute("SELECT decl,ord,name FROM map_modifiers ORDER BY decl,ord"):
            modifiers.setdefault(decl_ids[decl],[]).append(name)
        for i in range(len(out["decls"])):
            ins, outs = inner.get(i,[]), outer.get(i,[])
            out["bases"].append([ins,outs] if ins or outs else 0)
            out["variables"].append(variables.get(i,[]))
            out["modifiers"].append(modifiers.get(i,[]))
        for path, in db.execute("SELECT path FROM map_folders ORDER BY path"):
            out["folders"][path] = {}
        for path,kind,count in db.execute("SELECT path,kind,count FROM map_folder_counts ORDER BY path,kind"):
            out["folders"].setdefault(path,{})[kind] = count
        findings = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='map_snippets'").fetchone():
            out["sourceSnippets"] = {}
            for file,line,fingerprint,text in db.execute("SELECT file,line,input,snippet FROM map_snippets"):
                out["sourceSnippets"].setdefault(file,(fingerprint,{}))[1][line] = text
        out["finds"] = []
        for _,code,file,line,message,rule,decl,map_file,first_seen in db.execute(
                "SELECT ord,code,file,line,message,rule,decl,map_file,first_seen FROM map_findings ORDER BY file,line,code,message,rule"):
            findings.append((code,file,line,message,rule))
            out["finds"].append([code,file,line,message,decl_ids.get(decl,-1),file_ids.get(map_file,-1),first_seen])
        return out,findings


def enqueue(root, revision, stamp, work, findings, first_seen, previous, snippets):
    """Persist an output invalidation beside current findings; never read map geometry."""
    with ledger._TABLE_LOCK:
        db = ledger.table_connection(root,_MAP_REL,True)
        for sql in _MAP_TABLES.split(';'):
            if sql.strip(): db.execute(sql)
        with db:
            db.execute('BEGIN IMMEDIATE')
            head=db.execute('SELECT rev FROM map_head WHERE id=1').fetchone()
            if head is None or head[0] != previous:
                raise ValueError('map input revision changed before enqueue')
            db.execute('INSERT INTO map_work VALUES(?,?,?)',(revision,work['commit'],int(work['body'])))
            db.executemany('INSERT INTO map_work_files VALUES(?,?,?)',((revision,f,l) for f,l in work['files'].items()))
            db.executemany('INSERT INTO map_work_layers VALUES(?,?,?)',((revision,i,n) for i,n in enumerate(work['layers'])))
            db.executemany('INSERT INTO map_work_moves VALUES(?,?,?,?,?,?,?)',
                ((revision,f,i,*e) for f,edits in work['deltas'].items() for i,e in enumerate(edits)))
            db.executemany('INSERT INTO map_work_folders VALUES(?,?)',((revision,p) for p in work['folders']))
            db.executemany('INSERT INTO map_work_counts VALUES(?,?,?,?)',
                ((revision,p,k,n) for p,counts in work['folders'].items() for k,n in counts.items()))
            old=defaultdict(list)
            for row in db.execute('SELECT ord,code,file,line,message,rule FROM map_findings'):
                old[tuple(row[1:])].append(row[0])
            wanted=Counter(map(tuple,findings))
            for key,ids in old.items():
                db.executemany('DELETE FROM map_findings WHERE ord=?',((i,) for i in ids[wanted[key]:]))
            for key,count in wanted.items():
                for _ in range(count-len(old[key])):
                    db.execute('INSERT INTO map_findings(code,file,line,message,rule,decl,map_file,first_seen) VALUES(?,?,?,?,?,-1,-1,?)',(*key,first_seen.get(key,0)))
            db.execute('UPDATE map_head SET rev=?,stamp=?,structure_hash=? WHERE id=1',(revision,stamp,''))
            for file,(fingerprint,lines) in (snippets or {}).items():
                for line,text in lines.items():
                    db.execute('INSERT INTO map_snippets VALUES(?,?,?,?) ON CONFLICT(file,line) DO UPDATE SET input=excluded.input,snippet=excluded.snippet WHERE input!=excluded.input OR snippet!=excluded.snippet',(file,line,fingerprint,text))


def pending(root):
    """Return the next durable output job and its file-owned values."""
    with ledger._TABLE_LOCK:
        db=ledger.table_connection(root,_MAP_REL)
        if db is None or not db.execute("SELECT 1 FROM sqlite_master WHERE name='map_work'").fetchone(): return None
        row=db.execute('SELECT rev,commit_id,body FROM map_work ORDER BY rev LIMIT 1').fetchone()
        if row is None: return None
        revision,cid,body=row
        files=dict(db.execute('SELECT file,layer FROM map_work_files WHERE rev=?',(revision,)))
        layers=[n for n, in db.execute('SELECT name FROM map_work_layers WHERE rev=? ORDER BY ord',(revision,))]
        deltas,folders={},{}
        for file,_,a,b,c,d in db.execute('SELECT file,ord,a,b,c,d FROM map_work_moves WHERE rev=? ORDER BY file,ord',(revision,)):
            deltas.setdefault(file,[]).append((a,b,c,d))
        for path, in db.execute('SELECT path FROM map_work_folders WHERE rev=?',(revision,)): folders[path]={}
        for path,kind,count in db.execute('SELECT path,kind,count FROM map_work_counts WHERE rev=?',(revision,)):
            folders[path][kind]=count
        return dict(rev=revision,commit=cid,body=bool(body),files=files,layers=layers,deltas=deltas,folders=folders)


def patch_sql(root, work, fragment=None):
    """Apply one output job to owned rows, preserving unrelated IDs and relationships."""
    with ledger._TABLE_LOCK:
        db=ledger.table_connection(root,_MAP_REL)
        with db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM map_work WHERE rev=?',(work['rev'],)).fetchone(): return False
            ids={}
            for file in work['files']:
                row=db.execute('SELECT ord FROM map_files WHERE path=?',(file,)).fetchone()
                if row: ids[file]=row[0]
            if fragment is None:
                for file,edits in work['deltas'].items():
                    for i,kind,line,end in db.execute('SELECT ord,kind,line,end FROM map_decls WHERE file=?',(ids.get(file,-1),)).fetchall():
                        db.execute('UPDATE map_decls SET line=?,end=? WHERE ord=?',(1 if kind=='module' else diffmod.move_line(line,edits),diffmod.move_line(end,edits),i))
                        for ordinal,line,end,has_end in db.execute('SELECT ord,line,end,has_end FROM map_variables WHERE decl=?',(i,)).fetchall():
                            db.execute('UPDATE map_variables SET line=?,end=? WHERE decl=? AND ord=?',(diffmod.move_line(line,edits),diffmod.move_line(end,edits) if has_end else end,i,ordinal))
            else:
                db.execute('PRAGMA defer_foreign_keys=ON')
                # Only declarations belonging to the affected files are replaced.
                for fid in ids.values():
                    declarations=[i for i, in db.execute('SELECT ord FROM map_decls WHERE file=?',(fid,))]
                    for i in declarations:
                        db.execute('DELETE FROM map_edges WHERE source=? OR target=?',(i,i))
                        db.execute('DELETE FROM map_bases WHERE internal=?',(i,))
                        for table in ('map_bases','map_variables','map_modifiers','map_signatures'):
                            db.execute('DELETE FROM '+table+' WHERE decl=?',(i,))
                    db.execute('DELETE FROM map_decls WHERE file=?',(fid,))
                layers=dict((n,i) for i,n in db.execute('SELECT ord,name FROM map_layers'))
                for name in fragment['layers']:
                    if name not in layers:
                        layers[name]=db.execute('INSERT INTO map_layers(name) VALUES(?)',(name,)).lastrowid
                fm={}
                for i,(file,module) in enumerate(fragment['files']):
                    folder,layer=fragment['mods'][module]
                    layer=layers[fragment['layers'][layer]]
                    row=db.execute('SELECT ord FROM map_modules WHERE folder=? AND layer=?',(folder,layer)).fetchone()
                    mid=row[0] if row else db.execute('INSERT INTO map_modules(folder,layer) VALUES(?,?)',(folder,layer)).lastrowid
                    if file in ids:
                        fid=ids[file]
                        db.execute('UPDATE map_files SET module=? WHERE ord=?',(mid,fid))
                    else: fid=db.execute('INSERT INTO map_files(path,module) VALUES(?,?)',(file,mid)).lastrowid
                    fm[i]=fid
                for file in ids.keys()-{f for f,_ in fragment['files']}:
                    db.execute('DELETE FROM map_files WHERE ord=?',(ids[file],))
                dm={}
                for i,row in enumerate(fragment['decls']):
                    dm[i]=db.execute('INSERT INTO map_decls(name,kind,file,line,end,container,access,status) VALUES(?,?,?,?,?,-1,?,?)',(*row[:2],fm[row[2]],*row[3:5],*row[6:])).lastrowid
                for i,row in enumerate(fragment['decls']):
                    decl=dm[i]
                    db.execute('UPDATE map_decls SET container=? WHERE ord=?',(dm.get(row[5],-1),decl))
                    db.execute('INSERT INTO map_signatures VALUES(?,?,?)',(decl,*fragment['sig'][i]))
                    base=fragment['bases'][i]
                    if base:
                        db.executemany('INSERT INTO map_bases VALUES(?,?,?,?,?)',((decl,k,n,dm[v] if k=='internal' else None,v if k=='external' else None) for k,vs in zip(('internal','external'),base) for n,v in enumerate(vs)))
                    db.executemany('INSERT INTO map_variables VALUES(?,?,?,?,?,?,?,?)',((decl,n,v.get('name'),v.get('kind'),v.get('scope'),v.get('line'),v.get('end'),int('end' in v)) for n,v in enumerate(fragment['variables'][i])))
                    db.executemany('INSERT INTO map_modifiers VALUES(?,?,?)',((decl,n,v) for n,v in enumerate(fragment['modifiers'][i])))
                db.executemany('INSERT INTO map_edges(source,target,writing,bad,bypass) VALUES(?,?,?,?,?)',((dm[a],dm[b],w,bad,dm.get(bypass,bypass)) for a,b,w,bad,bypass in fragment['edges']))
                for file in work['files']:
                    folder=file.rsplit('/',1)[0] if '/' in file else ''
                    row=db.execute('SELECT ord FROM map_modules WHERE folder=?',(folder,)).fetchone()
                    if row: db.execute('DELETE FROM map_modules WHERE ord=? AND NOT EXISTS(SELECT 1 FROM map_files WHERE module=?)',(row[0],row[0]))
            for path,counts in work['folders'].items():
                db.execute('INSERT OR IGNORE INTO map_folders VALUES(?)',(path,))
                db.execute('DELETE FROM map_folder_counts WHERE path=?',(path,))
                db.executemany('INSERT INTO map_folder_counts VALUES(?,?,?)',((path,k,n) for k,n in counts.items()))
            for path,counts in work['folders'].items():
                if path and not counts and not db.execute('SELECT 1 FROM map_folder_counts WHERE path>=? AND path<? LIMIT 1',(path+'/',path+'/\uffff')).fetchone():
                    db.execute('DELETE FROM map_folder_counts WHERE path=?',(path,))
                    db.execute('DELETE FROM map_folders WHERE path=?',(path,))
            # Finding ownership is a view relation; update only affected/unbound rows.
            for file in set(work['files']) | {f for f, in db.execute('SELECT DISTINCT file FROM map_findings WHERE decl=-1 AND file IN (SELECT path FROM map_files)')}:
                row=db.execute('SELECT ord FROM map_files WHERE path=?',(file,)).fetchone()
                fid=row[0] if row else -1
                spans=db.execute('SELECT ord,line,end FROM map_decls WHERE file=? ORDER BY end-line,ord',(fid,)).fetchall()
                for ordinal,line in db.execute('SELECT ord,line FROM map_findings WHERE file=?',(file,)).fetchall():
                    owner=next((i for i,a,b in spans if a<=line<=b),-1)
                    db.execute('UPDATE map_findings SET decl=?,map_file=? WHERE ord=?',(owner,fid,ordinal))
            db.execute('DELETE FROM map_work WHERE rev=?',(work['rev'],))
            db.execute('INSERT OR REPLACE INTO map_projection VALUES(1,?)',(work['rev'],))
        return True



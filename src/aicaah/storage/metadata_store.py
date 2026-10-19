"""Scoped metadata and evidence queries over persisted relations."""
from storage import ledger, relations

FILE_RECORDS = ".spec-conformance/Cache/file-meta"


def places(root):
    """Read the published document/place relation in one SQL join, without record reconstruction."""
    rows = ledger.query_table(root, ".spec-conformance/Cache/document-places/index.row",
        "SELECT p.target,d.doc FROM document_places p JOIN record_details d ON d.record_file=p.record_file", ())
    result = {}
    for place,doc in rows:
        result.setdefault(place,set()).add(doc)
    return {place:sorted(docs) for place,docs in result.items()}


def declarations(root, file, limit, symbol=None, token=None, nested=False):
    query = 'SELECT n.key,n.symbol_id,n.owner_type,n.row_id FROM nodes n WHERE n.record_file=?'
    params = [file + '.row']
    if symbol:
        query += ' AND n.symbol_id=?'
        params.append(symbol)
    elif token and nested:
        escaped = lambda text: text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query += " AND n.key LIKE ? ESCAPE '\\'"
        params.append(escaped(file) + '#%.' + escaped(token) + '%')
    elif token:
        prefix = file + '#' + token
        query += ' AND n.key>=? AND n.key<?'
        params.extend((prefix, prefix + '\uffff'))
    return _node_query(root, FILE_RECORDS + '/' + file + '.row', query + ' LIMIT ?', tuple(params + [limit]))


def folder_types(root, folder, limit):
    return _node_query(root, FILE_RECORDS + '/' + folder + '/_',
        "SELECT key,symbol_id,owner_type,row_id FROM nodes WHERE kind IN ('클래스','구조체','인터페이스','열거형','대리자') "
        "AND key>=? AND key<? ORDER BY key LIMIT ?", (folder + '/', folder + '/\uffff', limit))


def members(root, anchor, owners, limit):
    if not owners:
        return []
    marks = ','.join('?' for _ in owners)
    return ledger.query_table(root, anchor,
        'SELECT key FROM nodes WHERE owner_type IN (' + marks + ') ORDER BY key LIMIT ?', tuple(owners) + (limit,))


def edges(root, anchor, symbols, limit, incoming=True):
    if not symbols:
        return []
    column = 'target' if incoming else 'source'
    marks = ','.join('?' for _ in symbols)
    owner = anchor.removeprefix(FILE_RECORDS + '/')
    if owner.endswith('/_'):
        prefix = owner[:-1]
        owner_filter = " AND r.source>=? AND r.source<? AND instr(substr(r.source,?),'/')=0"
        owner_params = (prefix, prefix + '\uffff', len(prefix) + 1)
    else:
        owner_filter = ' AND r.source=?'
        owner_params = (owner.removesuffix('.row'),)
    return ledger.query_table(root, anchor,
        'SELECT a.name,b.name,r.source,e.line,e.writing,e.guess FROM edges e '
        'JOIN symbols a ON a.id=e.source JOIN symbols b ON b.id=e.target JOIN records r ON r.file=e.file '
        'WHERE e.' + column + ' IN (SELECT id FROM symbols WHERE name IN (' + marks + '))' + owner_filter + ' LIMIT ?',
        tuple(symbols) + owner_params + (limit,))


def sibling_counts(root, folders, excluded_files):
    """Aggregate unaffected siblings without restoring their source/declaration records."""
    counts, siblings = {}, {}
    with ledger._TABLE_LOCK:
        db = ledger.table_connection(root, FILE_RECORDS + '/index.row')
        if db is None:
            return counts, siblings
        db.execute("SAVEPOINT metadata_scope")
        try:
            db.execute("CREATE TEMP TABLE IF NOT EXISTS metadata_changed(file TEXT PRIMARY KEY)")
            db.execute("DELETE FROM metadata_changed")
            db.executemany("INSERT INTO metadata_changed VALUES(?)", ((file,) for file in excluded_files))
            for folder in folders:
                counts[folder] = dict(db.execute("SELECT c.map_key,sum(c.value) FROM nodes n "
                    "JOIN node_counts c ON c.owner_id=n.row_id JOIN records r ON r.file=n.record_file "
                    "WHERE n.key=? AND n.kind='폴더' AND NOT EXISTS "
                    "(SELECT 1 FROM metadata_changed x WHERE x.file=r.source) GROUP BY c.map_key", (folder,)))
                siblings[folder] = db.execute("SELECT n.file,c.map_key,c.value FROM nodes n "
                    "JOIN node_counts c ON c.owner_id=n.row_id JOIN records r ON r.file=n.record_file "
                    "WHERE n.parent=? AND n.kind='파일' AND c.map_key IN ('메서드','변수') AND NOT EXISTS "
                    "(SELECT 1 FROM metadata_changed x WHERE x.file=r.source)", (folder,)).fetchall()
            db.execute("RELEASE metadata_scope")
        except BaseException:
            db.execute("ROLLBACK TO metadata_scope")
            db.execute("RELEASE metadata_scope")
            raise
    return counts, siblings


def _node_query(root, anchor, query, parameters):
    """Fetch bounded declaration rows and their counts/modifiers through SQL foreign keys."""
    rows = ledger.query_table(root,anchor,query,parameters)
    if not rows: return []
    ids = [row[3] for row in rows]
    marks = ','.join('?' for _ in ids)
    columns = ','.join('"'+key+'"' for key,_ in relations.NODES.columns)
    values = ledger.query_table(root,anchor,'SELECT row_id,fields,'+columns+' FROM nodes WHERE row_id IN ('+marks+')',ids)
    facts = {row_id:{key:value for i,((key,_),value) in enumerate(zip(relations.NODES.columns,data)) if fields & (1<<i)}
             for row_id,fields,*data in values}
    for row_id,fields,*_ in values:
        if fields & (1 << len(relations.NODES.columns)): facts[row_id]['counts'] = {}
        if fields & (1 << (len(relations.NODES.columns)+1)): facts[row_id]['modifiers'] = []
    for owner,key,value in ledger.query_table(root,anchor,'SELECT owner_id,map_key,value FROM node_counts WHERE owner_id IN ('+marks+')',ids):
        facts[owner]['counts'][key] = value
    for owner,value in ledger.query_table(root,anchor,'SELECT owner_id,modifier FROM node_modifiers WHERE owner_id IN ('+marks+') ORDER BY ordinal',ids):
        facts[owner]['modifiers'].append(value)
    return [(key,symbol,owner,facts[row_id]) for key,symbol,owner,row_id in rows]

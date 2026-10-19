"""Fixed relational schemas for source declarations and their owned facts.

Only the named columns and relationships below are accepted. No object graph,
opaque payload, dynamically named table, or serialized collection is stored.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Table:
    name: str
    columns: tuple = ()
    children: tuple = ()
    shape: str = "object"


def cols(text, kind="TEXT"):
    return tuple((name, kind) for name in text.split())


def sequence(name, columns, shape="tuple"):
    return Table(name, columns, shape=shape)


SOURCE_MODIFIERS = sequence("source_modifiers", cols("modifier"), "scalar")
SOURCE_DECLARATIONS = Table("source_declarations",
    cols("file path kind name signature params access body value type") +
    cols("line end", "INTEGER") + cols("documented", "BOOLEAN"),
    (("modifiers", SOURCE_MODIFIERS, "many"),))
SOURCE_EDITS = sequence("source_edits", cols("old_start old_end new_start new_end", "INTEGER"))
SOURCE_RANGE = sequence("source_parse_range", cols("old_start old_end new_start new_end", "INTEGER"))
SOURCE_DELTA = Table("source_delta", cols("previous") + cols("positionOnly", "BOOLEAN"),
    (("edits", SOURCE_EDITS, "many"), ("parseRange", SOURCE_RANGE, "one")))
SOURCE_ENTRY = Table("source_entries", cols("sha256 unit error contextHash") +
    cols("mtime", "REAL") + cols("ctime size parser", "INTEGER"),
    (("symbols", SOURCE_DECLARATIONS, "many"), ("delta", SOURCE_DELTA, "one")))

NODE_COUNTS = sequence("node_counts", cols("value", "INTEGER"), "scalar")
NODE_MODIFIERS = sequence("node_modifiers", cols("modifier"), "scalar")
NODES = Table("nodes", cols("key symbol_id owner_type parent kind name file layer folder source_kind occurrence_id alias") +
    cols("line end", "INTEGER"), (("counts", NODE_COUNTS, "map"), ("modifiers", NODE_MODIFIERS, "many")))
PLACES = sequence("document_places", cols("target"), "scalar")
DOCUMENT_HASHES = sequence("ledger_documents", cols("hash"), "scalar")
HEADER = Table("ledger_header", cols("origin") + cols("rev", "INTEGER") + cols("rebuildPending", "BOOLEAN"),
    (("docs", DOCUMENT_HASHES, "map"),))

COMP_FILES = sequence("compilation_files", cols("path"), "scalar")
COMP_OCCURRENCES = Table("declaration_occurrences", cols("file") + cols("line end", "INTEGER"))
COMP_VARIABLES = Table("declaration_variables", cols("name kind scope") + cols("line", "INTEGER"))
COMP_MODIFIERS = sequence("declaration_modifiers", cols("modifier"), "scalar")
COMP_ATTRIBUTES = sequence("declaration_attributes", cols("attribute"), "scalar")
COMP_BASES = sequence("declaration_bases", cols("base"), "scalar")
COMP_DECLS = Table("code_declarations", cols("key name source_name source_params kind access type hash") +
    cols("file line end container stmts locals", "INTEGER"),
    (("occurrences", COMP_OCCURRENCES, "many"), ("variables", COMP_VARIABLES, "many"),
     ("mods", COMP_MODIFIERS, "many"), ("attrs", COMP_ATTRIBUTES, "many"), ("bases", COMP_BASES, "many")))
COMP_EDGES = sequence("code_references", cols("source target source_file line writing", "INTEGER"), "list")
COMP_OVERRIDES = sequence("code_overrides", cols("source target explicit", "INTEGER"), "list")
COMP_STRINGS = sequence("code_string_uses", cols("source source_file line", "INTEGER") + cols("api text") + cols("argument", "INTEGER"), "list")
COMP_UNRESOLVED = sequence("code_unresolved", cols("source source_file line", "INTEGER") + cols("lookup_name"), "list")
COMP_DIAGNOSTICS = Table("code_diagnostics", cols("file code message") + cols("line", "INTEGER"))
COMP_UNITS = Table("compilation_units", cols("name") + cols("errors walked ms", "INTEGER"))
COMPILATION = Table("compilations", cols("inputKey") + cols("version", "INTEGER"),
    tuple((key, model, "many") for key, model in (
        ("files", COMP_FILES), ("decls", COMP_DECLS), ("edges", COMP_EDGES), ("overrides", COMP_OVERRIDES),
        ("strings", COMP_STRINGS), ("unresolved", COMP_UNRESOLVED), ("diagnostics", COMP_DIAGNOSTICS), ("units", COMP_UNITS))))

RUNTIME = sequence("server_runtime", cols("root unity python executable engine"))
WORKFLOW = sequence("server_workflow", cols("mode policy") + cols("request_stamp", "INTEGER"))
SEEN = sequence("server_inputs", cols("path") + cols("mtime size ctime", "INTEGER"))
WATCH_CELLS = sequence("server_watch_cells", cols("name value"))
# A watch row is a list of named column values, not an arbitrary nested object.
WATCH = Table("server_watch", children=(("cells", WATCH_CELLS, "many"),))
PRODUCER_VERSIONS = sequence("server_producers", cols("version"), "scalar")
SERVER_SETTINGS = sequence("server_settings", cols("fingerprint"), "scalar")

PY_BASES = sequence("python_bases", cols("target"), "scalar")
PY_DECLS = Table("python_declarations", cols("key name kind container access") + cols("line end", "INTEGER"),
                 (("bases", PY_BASES, "many"),))
PY_IMPORTS = Table("python_imports", cols("kind module name alias") + cols("level", "INTEGER"))
PY_NAMES = sequence("python_names", cols("name target"))
PY_ATTRIBUTES = sequence("python_attribute_lookups", cols("name"), "scalar")
PY_OCCURRENCES = sequence("python_occurrences", cols("line", "INTEGER") + cols("scope name target"))
PY_SYNTAX = Table("python_files", cols("input") + cols("end", "INTEGER"),
    (("declarations", PY_DECLS, "many"), ("imports", PY_IMPORTS, "many"), ("names", PY_NAMES, "many"),
     ("attributes", PY_ATTRIBUTES, "many"), ("occurrences", PY_OCCURRENCES, "many")))

ROOT = Table("record_details", cols("checker doc source") + cols("rev", "INTEGER"),
    (("entry", SOURCE_ENTRY, "one"), ("nodes", NODES, "many"), ("places", PLACES, "many"),
     ("header", HEADER, "one"), ("data", COMPILATION, "one"), ("runtime", RUNTIME, "one"),
     ("workflow", WORKFLOW, "one"), ("seen", SEEN, "many"), ("watch", WATCH, "many"),
     ("syntax", PY_SYNTAX, "one"), ("producers", PRODUCER_VERSIONS, "map"), ("settings", SERVER_SETTINGS, "one")))


def schema(model, parent=None):
    """DDL is generated only from the fixed schema declarations, never input keys."""
    owner = "owner_id INTEGER" + (f' REFERENCES "{parent}"(row_id) ON DELETE CASCADE' if parent else "")
    definitions = ["row_id INTEGER PRIMARY KEY", "record_file TEXT NOT NULL REFERENCES records(file) ON DELETE CASCADE",
                   owner, "ordinal INTEGER NOT NULL", "map_key TEXT", "fields INTEGER NOT NULL", "tuples INTEGER NOT NULL"]
    definitions += [f'"{name}" {"INTEGER" if kind == "BOOLEAN" else kind}' for name, kind in model.columns]
    result = [f'CREATE TABLE IF NOT EXISTS "{model.name}" ({",".join(definitions)})',
              f'CREATE INDEX IF NOT EXISTS "{model.name}_record" ON "{model.name}"(record_file,owner_id,ordinal)']
    if parent:
        result.append(f'CREATE INDEX IF NOT EXISTS "{model.name}_owner" ON "{model.name}"(owner_id)')
    for _, child, _ in model.children:
        result.extend(schema(child, model.name))
    return result


def prepare(connection, model=ROOT):
    for sql in schema(model):
        connection.execute(sql)
    if model is ROOT:
        for column in ("module","name"):
            connection.execute(f'CREATE INDEX IF NOT EXISTS "python_imports_{column}" ON python_imports("{column}",record_file)')
        for table,column in (("compilation_files","path"),("code_declarations","hash"),
                             ("code_declarations","name"),("code_unresolved","lookup_name")):
            connection.execute(f'CREATE INDEX IF NOT EXISTS "{table}_{column}" ON "{table}"("{column}",record_file)')
        for column in ("key", "symbol_id", "owner_type", "parent"):
            connection.execute(f'CREATE INDEX IF NOT EXISTS "nodes_{column}" ON nodes("{column}")')
        for table,column in (("code_references","source_file"),("code_string_uses","source_file"),
                             ("code_unresolved","source_file"),("code_declarations","file"),("code_overrides","source")):
            connection.execute(f'CREATE INDEX IF NOT EXISTS "{table}_source_file" ON "{table}"(record_file,"{column}",ordinal)')


def insert(connection, file, model, values, owner=None):
    """Insert explicit scalar columns and child foreign keys in the caller's transaction."""
    pending = []
    for ordinal, (map_key, value) in enumerate(values):
        if model.shape == "scalar":
            value = {model.columns[0][0]: value}
        elif model.shape in ("tuple", "list"):
            if not isinstance(value, (list, tuple)) or len(value) != len(model.columns):
                raise ValueError("invalid row: " + model.name)
            value = dict(zip((c[0] for c in model.columns), value))
        allowed = {c[0] for c in model.columns} | {c[0] for c in model.children}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError("unknown columns in " + model.name + ": " + str(sorted(unknown)))
        fields = sum(1 << i for i, (key, _) in enumerate(model.columns) if key in value)
        tuples = 0
        for i, (key, _, mode) in enumerate(model.children, len(model.columns)):
            if key in value:
                fields |= 1 << i
                if isinstance(value[key], tuple): tuples |= 1 << i
                if value[key] is None: raise ValueError("null relation: " + key)
        columns = ["record_file", "owner_id", "ordinal", "map_key", "fields", "tuples"] + [c[0] for c in model.columns]
        args = [file, owner, ordinal, map_key, fields, tuples]
        for key, kind in model.columns:
            scalar = value.get(key)
            if scalar is not None:
                expected = {"TEXT": str, "INTEGER": int, "BOOLEAN": (bool, int), "REAL": (float, int)}[kind]
                if not isinstance(scalar, expected): raise ValueError("non-scalar/wrong type: " + model.name + "." + key)
            args.append(scalar)
        quoted = ','.join('"' + c + '"' for c in columns)
        row_id = connection.execute(f'INSERT INTO "{model.name}" ({quoted}) VALUES ({",".join("?" for _ in args)})', args).lastrowid
        pending.append((row_id, value))
    for row_id, value in pending:
        for key, child, mode in model.children:
            if key not in value: continue
            data = value[key]
            items = list(data.items()) if mode == "map" else [(None, v) for v in data] if mode == "many" else [(None, data)]
            insert(connection, file, child, items, row_id)


def select(connection, file, model=ROOT, owners=None):
    """Read each domain table once and join child rows by their foreign keys."""
    columns = [c[0] for c in model.columns]
    quoted = ','.join('"' + c + '"' for c in columns)
    predicate,params = '',[file]
    if owners is not None and model in (COMP_EDGES,COMP_STRINGS,COMP_UNRESOLVED,COMP_OVERRIDES):
        marks=','.join('?' for _ in owners) or 'NULL'
        files=f'SELECT ordinal FROM compilation_files WHERE record_file=? AND path IN ({marks})'
        if model is COMP_OVERRIDES:
            predicate=f' AND source IN (SELECT ordinal FROM code_declarations WHERE record_file=? AND file IN ({files}))'
            params.append(file)
        else:
            predicate=f' AND source_file IN ({files})'
        params.extend((file,*owners))
    raw = connection.execute(f'SELECT row_id,owner_id,map_key,fields,tuples{"," if columns else ""}{quoted} '
                             f'FROM "{model.name}" WHERE record_file=?{predicate} ORDER BY ordinal', params).fetchall()
    # Empty owners never trigger scans of their child tables.
    children = {key: select(connection, file, child, owners) for i, (key, child, _) in enumerate(model.children, len(columns))
                if any(row[3] & (1 << i) for row in raw)}
    result = {}
    for row_id, owner, map_key, fields, tuples, *data in raw:
        if model.shape in ("scalar","tuple","list"):
            if fields != (1 << len(columns))-1: raise ValueError("incomplete row: " + model.name)
            value = data[0] if model.shape == "scalar" else tuple(data) if model.shape == "tuple" else data
            result.setdefault(owner, []).append((map_key,value))
            continue
        value = {key: (bool(item) if kind == "BOOLEAN" and item is not None else item)
                 for i, ((key, kind), item) in enumerate(zip(model.columns, data)) if fields & (1 << i)}
        for i, (key, child, mode) in enumerate(model.children, len(columns)):
            if not fields & (1 << i): continue
            rows = children[key].get(row_id, [])
            if mode == "one":
                if len(rows) != 1: raise ValueError("missing related row: " + child.name)
                value[key] = rows[0][1]
            elif mode == "map": value[key] = dict(rows)
            else:
                items = [v for _, v in rows]
                value[key] = tuple(items) if tuples & (1 << i) else items
        result.setdefault(owner, []).append((map_key, value))
    return result


def select_many(connection, files, model=ROOT):
    """Read one domain's typed relation rows for several files in bounded SQL batches."""
    files = tuple(files)
    if not files:
        return {}
    columns = [column[0] for column in model.columns]
    quoted = ','.join('"' + column + '"' for column in columns)
    raw = []
    for start in range(0, len(files), 400):
        batch = files[start:start + 400]
        marks = ','.join('?' for _ in batch)
        raw.extend(connection.execute(
            f'SELECT record_file,row_id,owner_id,map_key,fields,tuples'
            f'{"," if columns else ""}{quoted} FROM "{model.name}" '
            f'WHERE record_file IN ({marks}) ORDER BY record_file,owner_id,ordinal', batch).fetchall())
    children = {key: select_many(connection, files, child)
                for index, (key, child, _) in enumerate(model.children, len(columns))
                if any(row[4] & (1 << index) for row in raw)}
    result = {}
    for file, row_id, owner, map_key, fields, tuples, *data in raw:
        if model.shape in ('scalar', 'tuple', 'list'):
            if fields != (1 << len(columns)) - 1:
                raise ValueError('incomplete row: ' + model.name)
            value = data[0] if model.shape == 'scalar' else tuple(data) if model.shape == 'tuple' else data
        else:
            value = {key: (bool(item) if kind == 'BOOLEAN' and item is not None else item)
                     for index, ((key, kind), item) in enumerate(zip(model.columns, data))
                     if fields & (1 << index)}
            for index, (key, child, mode) in enumerate(model.children, len(columns)):
                if not fields & (1 << index):
                    continue
                rows = children[key].get(row_id, [])
                if mode == 'one':
                    if len(rows) != 1:
                        raise ValueError('missing related row: ' + child.name)
                    value[key] = rows[0][1]
                elif mode == 'map':
                    value[key] = dict(rows)
                else:
                    items = [item for _, item in rows]
                    value[key] = tuple(items) if tuples & (1 << index) else items
        result.setdefault(file if model is ROOT else owner, []).append((map_key, value))
    return result

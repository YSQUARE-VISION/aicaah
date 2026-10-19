"""Independent presentation consumer of committed, file-scoped SQL updates."""
import threading
import time
import traceback
from types import SimpleNamespace

from storage import map_store, change_store
from graph import refs
from output import codemap


class Presentation:
    """Own a single output thread; diagnosis/approval only send wake-up signals."""

    def __init__(self, root):
        self.root = root
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.lock = threading.RLock()
        self.thread = None
        self.revision = None
        self.error = ''
        self.seconds = 0.0

    def start(self):
        if self.thread is None:
            self.thread = threading.Thread(target=self.run, name='harness-presentation', daemon=True)
            self.thread.start()
        self.wake.set()

    def notify(self):
        self.wake.set()

    def run(self):
        while not self.stopping.is_set():
            self.wake.wait()
            self.wake.clear()
            if self.stopping.is_set(): break
            try:
                self.flush()
            except Exception:
                self.error = traceback.format_exc()

    def flush(self):
        """Consume durable jobs in order, without a full-map restore or HTML output."""
        with self.lock:
            start=time.perf_counter()
            processed=False
            while not self.stopping.is_set():
                work=map_store.pending(self.root)
                if work is None: break
                fragment=None
                if not work['body']:
                    saved=change_store.read(self.root,work['commit'])
                    graph=refs.Graph(**saved['graph'])
                    analysis=SimpleNamespace(graph=graph,
                        rows=[SimpleNamespace(name=n) for n in work['layers']],
                        file_layer=[work['files'].get(f) for f in graph.files],
                        status=saved['status'],bad_edges=saved['bad_edges'])
                    fragment=codemap.data(analysis,[],[], '',cur=saved['after'])
                if map_store.patch_sql(self.root,work,fragment):
                    self.revision=work['rev']
                    processed=True
            self.error=''
            if processed: self.seconds=time.perf_counter()-start

    def close(self):
        self.stopping.set()
        self.wake.set()
        if self.thread is not None:
            self.thread.join(timeout=5)


class Projection(dict):
    """Diagnostic headers are immediate; geometry is read only by a view consumer."""

    def __init__(self, root, header, current, presenter):
        super().__init__(header)
        self.root, self.current, self.presenter = root, current, presenter

    def __missing__(self, key):
        if key not in {'layers','mods','files','decls','edges','finds','sig','bases','variables','modifiers','folders','sourceFiles'}:
            raise KeyError(key)
        self.presenter.flush()
        loaded=codemap.load_sql(self.root,self['rev'],self.current)
        if loaded is None:
            raise ValueError('requested map revision is no longer current')
        self.update(loaded[0])
        return self[key]

    def get(self, key, default=None):
        try: return self[key]
        except KeyError: return default



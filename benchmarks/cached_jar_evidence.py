"""Separate resource candidate; frozen bounded_jar_evidence remains unchanged."""
import zipfile
from contextlib import ExitStack

from bounded_jar_evidence import BudgetExceeded
from bounded_jar_evidence import JarFiles as FrozenJarFiles

from sbom_creator import payload


class JarFiles(FrozenJarFiles):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failed_layers = {}
        self.failed_archives = {}
        self.stats.update(layer_failure_hits=0, archive_failure_hits=0)

    def _isolated(self, function, *args):
        """Release contexts acquired by a failed attempt, retain successful ones."""
        parent, attempt = self.stack, ExitStack()
        before = {name: set(getattr(self, name)) for name in ('opened', 'spools', 'zips')}
        self.stack = attempt
        try:
            result = function(*args)
        except BaseException:
            attempt.close()
            # Failed file reads can follow a successful new layer index. Its
            # stream was just closed, so never leave that index reusable.
            for name, keys in before.items():
                values = getattr(self, name)
                for key in set(values) - keys:
                    del values[key]
            raise
        else:
            parent.enter_context(attempt)
            return result
        finally:
            self.stack = parent

    def source(self, name):
        entry = self.files.get(payload.path(name), {})
        layer = entry.get('location', {}).get('layerID')
        if layer in self.failed_layers:
            self.stats['layer_failure_hits'] += 1
            kind, message = self.failed_layers[layer]
            raise kind(message)
        try:
            return self._isolated(super().source, name)
        except ValueError as error:
            # Only errors about the immutable layer index poison that layer.
            # A bad file path/size or exhausted copy budget must not poison peers.
            if layer in self.layers and str(error) in (
                    'Layer index/expanded-byte budget', 'Ambiguous layer path',
                    'Layer is not a regular file'):
                self.failed_layers[layer] = (type(error), str(error))
            raise

    def archive(self, key, stream):
        if key in self.zips:
            return self.zips[key]
        if key in self.failed_archives:
            self.stats['archive_failure_hits'] += 1
            kind, message = self.failed_archives[key]
            raise kind(message)
        if len(self.failed_archives) >= 256:
            raise BudgetExceeded('Rejected archive cache budget')
        try:
            return self._isolated(super().archive, key, stream)
        except (ValueError, zipfile.BadZipFile) as error:
            self.failed_archives[key] = (type(error), str(error))
            raise

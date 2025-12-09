# config/context_patch.py
from django.template import Context


class PatchedContext(Context):
    def __copy__(self):
        duplicate = super().__copy__()
        if not hasattr(duplicate, "dicts"):
            duplicate.dicts = []
        return duplicate

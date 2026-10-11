"""
Match patch symbols against atom slices (usages / reachables).

Intended location: ``scanpipe/pipes/atom.py``.

Atom names Python symbols like ``pkg/mod.py:<module>.Class.method``; these are
normalised to dotted names (``pkg.mod.Class.method``) so that a patch
``qualified_name`` can be matched with dot-boundary suffix matching.

``match_patches_to_resources`` is the single entry point used by the
``AtomReachability`` pipeline; everything else is private.

Contract with ``AtomTool.parsed_output``
----------------------------------------
``resource_indexes`` accepts either shape:

- single-language (what ``AtomTool.parsed_output`` returns today):
  ``{"usages": <slice data>, "reachables": <slice data>}``
- multi-language: ``{"languages": {lang: {"usages": ..., "reachables": ...}},
  "failed": [lang, ...]}``

Assumptions to verify against real data (all isolated in this file):
- usages slice: call sites are dicts carrying ``callName`` / ``resolvedMethod``,
  and the enclosing method is a dict carrying ``fullName`` (inferred from
  atom-tools' README and from real b2sdk / vulnerablecode slices).
- reachables slice: flow nodes carry ``fullName`` / ``resolvedMethod`` /
  ``callName`` / ``parentMethodName`` (NOT verified: reachables crashed or
  returned no flows in the runs so far).
- ``patch_symbols`` shape: see ``_iter_patch_symbols``.
"""

import re
from collections import Counter
from collections import defaultdict
from dataclasses import asdict
from dataclasses import dataclass

from scanpipe.pipes.reachability import ReachabilityStatus

MODULE_SEP = ":<module>."
SYNTHETIC_MARKER = "<metaClassAdapter>"
MAX_EVIDENCE = 25

# slice key -> kind of hit it produces
USAGE_KEYS = {"fullName": "definition", "callName": "call", "resolvedMethod": "call"}
FLOW_KEYS = dict.fromkeys(
    ("fullName", "resolvedMethod", "callName", "parentMethodName"), "flow"
)

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|testing)/"
    r"|(^|/)tests?\.py$"
    r"|(^|/)test_[^/]*$"
    r"|_tests?\.(py|java)$"
    r"|(^|/)conftest\.py$"
)


@dataclass(frozen=True, slots=True)
class Hit:
    kind: str  # "call" | "definition" | "flow"
    name: str  # normalised dotted name
    file: str | None = None
    line: int | None = None


def is_test_path(path):
    """Return True for paths that look like test code."""
    return bool(path and TEST_PATH_RE.search(path.replace("\\", "/")))


def clean_slice_path(path):
    """Normalise a slice ``fileName`` to a clean, forward-slash path."""
    return re.sub(r"^(\./)+", "", path.replace("\\", "/")).lstrip("/")


def module_from_path(path):
    """``pkg/mod.py`` -> ``pkg.mod``; ``pkg/__init__.py`` -> ``pkg``."""
    path = clean_slice_path(path)
    path = re.sub(r"\.(py|java)$", "", path)
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    elif path == "__init__":
        path = ""
    return path.replace("/", ".")


def normalize_name(raw):
    """``a/b.py:<module>.C.m`` -> ``a.b.C.m``; Java ``p.C.m:sig`` -> ``p.C.m``."""
    if MODULE_SEP in raw:
        file_part, local = raw.split(MODULE_SEP, 1)
        module = module_from_path(file_part)
        return f"{module}.{local}" if module else local
    return raw.split(":", 1)[0].strip()


def names_match(index_name, symbol):
    """Return True when either name is a dot-boundary suffix of the other."""
    return (
        index_name == symbol
        or index_name.endswith("." + symbol)
        or symbol.endswith("." + index_name)
    )


def _walk(node, file_name=None):
    """Yield ``(dict, nearest enclosing fileName)`` for every dict in the slice."""
    if isinstance(node, dict):
        file_name = node.get("fileName") or node.get("parentFileName") or file_name
        yield node, file_name
        for value in node.values():
            yield from _walk(value, file_name)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, file_name)


def extract_hits(slice_data, key_kinds):
    """Collect one ``Hit`` per (slice key, dict) pair found anywhere in the slice."""
    hits = {}  # dict used as an insertion-ordered set, to dedup identical hits
    for node, file_name in _walk(slice_data):
        for key, kind in key_kinds.items():
            value = node.get(key)
            if isinstance(value, str) and value and SYNTHETIC_MARKER not in value:
                hit = Hit(
                    kind=kind,
                    name=normalize_name(value),
                    file=file_name,
                    line=node.get("lineNumber"),
                )
                hits[hit] = None
    return list(hits)


class SliceIndex:
    """The hits of one language's slices, indexed by the last name segment."""

    def __init__(self, usages=None, reachables=None):
        self.has_usages = usages is not None
        hits = extract_hits(usages, USAGE_KEYS) if usages is not None else []
        if reachables is not None:
            hits += extract_hits(reachables, FLOW_KEYS)
        self.by_tail = defaultdict(list)
        for hit in hits:
            self.by_tail[hit.name.rsplit(".", 1)[-1]].append(hit)

    def lookup(self, symbol):
        """Return the hits whose name matches ``symbol`` (suffix match)."""
        tail = symbol.rsplit(".", 1)[-1]
        return [
            hit
            for hit in self.by_tail.get(tail, ())
            if names_match(hit.name, symbol)
        ]


def classify_symbol(symbol, indexes, failed_languages=()):
    """
    Classify one patch symbol from the hits it produced in the slices.

    - REACHABLE: the symbol is in a ``reachables`` flow, or has a call site in
      non-test code (no entry-point path is proven).
    - NOT_REACHABLE: the symbol is absent, or only used in tests.
    - UNKNOWN: no usable slices, the analysis failed for some language, or the
      symbol is defined in non-test code but never called, so absence proves
      nothing.
    """
    hits = [hit for index in indexes for hit in index.lookup(symbol)]
    prod = [hit for hit in hits if not is_test_path(hit.file)]
    prod_kinds = {hit.kind for hit in prod}

    if "flow" in prod_kinds:
        status, reason = ReachabilityStatus.REACHABLE, "flow_from_tagged_source"
    elif "call" in prod_kinds:
        status, reason = ReachabilityStatus.REACHABLE, "call_site_found"
    elif not any(index.has_usages for index in indexes):
        status, reason = ReachabilityStatus.UNKNOWN, "no_slices_available"
    elif failed_languages:
        status = ReachabilityStatus.UNKNOWN
        reason = f"analysis_failed_for:{','.join(failed_languages)}"
    elif prod:  # only definitions are left: nothing in the slices calls it
        status, reason = ReachabilityStatus.UNKNOWN, "defined_but_never_called"
    elif hits:
        status, reason = ReachabilityStatus.NOT_REACHABLE, "only_in_tests"
    else:
        status, reason = ReachabilityStatus.NOT_REACHABLE, "not_found"

    # Production hits first, then by file and line, for stable evidence.
    ordered = sorted(
        hits,
        key=lambda hit: (
            is_test_path(hit.file),
            hit.file or "",
            hit.line or 0,
            hit.kind,
        ),
    )
    return {
        "symbol": symbol,
        "status": status,
        "reason": reason,
        "evidence": [asdict(hit) for hit in ordered[:MAX_EVIDENCE]],
    }


def _symbol_names(value):
    """Yield symbol names from strings, ``qualified_name`` objects or containers."""
    if isinstance(value, str):
        if value:
            yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _symbol_names(item)
    elif getattr(value, "qualified_name", None):
        yield value.qualified_name
    elif hasattr(value, "__iter__"):
        for item in value:
            yield from _symbol_names(item)


def _iter_patch_symbols(patch_symbols):
    """
    Yield ``(patch_label, symbol_name)``.

    ADAPTER: adjust this if the shape of ``patch_symbols`` differs (accepts a
    dict of patch -> symbols, or a flat collection of symbols).
    """
    if isinstance(patch_symbols, dict):
        groups = patch_symbols.items()
    else:
        groups = [("", patch_symbols)]
    for patch, symbols in groups:
        for name in dict.fromkeys(_symbol_names(symbols)):
            yield str(patch), name


class _ResourceLookup:
    """
    Look up codebase resources by path, tolerating extra or missing directory
    prefixes in the slice ``fileName`` (e.g., absolute paths, ``./`` prefixes).
    """

    def __init__(self, resources):
        self.by_name = defaultdict(list)
        for resource in resources:
            self.by_name[resource.path.rsplit("/", 1)[-1]].append(resource)

    def find(self, file_name):
        if not file_name:
            return None
        file_name = clean_slice_path(file_name)
        for resource in self.by_name.get(file_name.rsplit("/", 1)[-1], ()):
            path = resource.path
            if (
                path == file_name
                or path.endswith("/" + file_name)
                or file_name.endswith("/" + path)
            ):
                return resource
        return None


def _build_indexes(resource_indexes):
    """
    Return ``(indexes, failed_languages)`` from a ``parsed_output`` result.

    Accepts either the flat single-language shape produced by
    ``AtomTool.parsed_output`` (``{"usages": ..., "reachables": ...}``) or a
    multi-language shape (``{"languages": {...}, "failed": [...]}``).
    """
    resource_indexes = resource_indexes or {}
    if "languages" in resource_indexes:
        groups = (resource_indexes.get("languages") or {}).values()
        failed = tuple(resource_indexes.get("failed") or ())
    else:
        groups = [resource_indexes]
        failed = ()
    indexes = [
        SliceIndex(group.get("usages"), group.get("reachables")) for group in groups
    ]
    return indexes, failed


def _store_evidence_on_resources(results, lookup):
    """Store one entry per (result, file) on matching resources. Return the count."""
    stored = {}  # resource path -> (resource, entries)
    for result in results:
        by_file = defaultdict(list)
        for evidence in result["evidence"]:
            by_file[evidence["file"]].append(evidence)
        for file_name, evidence in by_file.items():
            resource = lookup.find(file_name)
            if resource is None:
                continue
            _, entries = stored.setdefault(resource.path, (resource, []))
            entries.append({**result, "evidence": evidence})

    for resource, entries in stored.values():
        resource.update_extra_data({"symbols_reachability": entries})
    return len(stored)


def match_patches_to_resources(
    tool_name,
    patches,
    patch_symbols,
    resource_indexes,
    candidate_resources,
    logger=None,
):
    """
    Classify every patch symbol and store the evidence on the matching
    resources under ``extra_data["symbols_reachability"]``.

    ``resource_indexes`` is the output of ``AtomTool.parsed_output``; ``patches``
    is accepted for signature compatibility. Returns the per-symbol results,
    including the NOT_REACHABLE / UNKNOWN verdicts that have no resource to
    live on.
    """
    indexes, failed = _build_indexes(resource_indexes)
    lookup = _ResourceLookup(candidate_resources)

    results = []
    for patch, symbol in _iter_patch_symbols(patch_symbols):
        results.append(
            {
                **classify_symbol(symbol, indexes, failed),
                "tool": tool_name,
                "patch": patch,
            }
        )

    stored = _store_evidence_on_resources(results, lookup)

    if logger:
        counts = Counter(result["status"] for result in results)
        logger(f"atom reachability: {len(results)} symbols -> {dict(counts)}")
        logger(f"atom reachability: evidence stored on {stored} resources")
    return results
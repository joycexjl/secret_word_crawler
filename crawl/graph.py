"""Edge records, node model, DOT export, post-hoc depth (design §5/§6).

Edges are the highest-value artifact in the system: each records *how* a
reference was discovered (`a_href`, `xhr`, `js_navigation`, `regex_fallback`,
…). Nodes are resources — derived from the manifest plus any `dst` never
fetched (out-of-scope or errored).

Depth for reporting is POST-HOC BFS distance from `/` over the edge graph,
computed at export — not first-seen order, which is mechanism-accidental.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path

HOW_STYLES = {
    "a_href": ("black", "solid"),
    "img_src": ("gray40", "solid"),
    "srcset": ("gray40", "dashed"),
    "picture_source": ("gray40", "dashed"),
    "css_url": ("darkgreen", "solid"),
    "link_rel": ("darkgreen", "dashed"),
    "script_src": ("darkorange", "solid"),
    "iframe_src": ("purple", "solid"),
    "object_data": ("purple", "solid"),
    "embed_src": ("purple", "solid"),
    "form_action": ("brown", "solid"),
    "area_href": ("gray40", "dotted"),
    "meta_refresh": ("brown", "dashed"),
    "xhr": ("red", "bold"),
    "js_navigation": ("red", "solid"),
    "click": ("red", "dotted"),
    "redirect": ("blue", "dashed"),
    "header_link": ("blue", "dotted"),
    "regex_fallback": ("magenta", "bold"),
    "shadow_dom": ("darkgreen", "bold"),
    "data_attr": ("gray40", "dotted"),
    "poster": ("gray40", "solid"),
}


class EdgeStore:
    """Append-only edges.jsonl — one record per reference."""

    def __init__(self, root: Path):
        self.path = Path(root) / "edges.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, *, src: str, dst: str, how: str, hint: str, depth: int) -> None:
        self._fh.write(json.dumps(
            {"src": src, "dst": dst, "how": how, "hint": hint, "depth": depth},
            sort_keys=True,
        ) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


def load_edges(root: Path) -> list[dict]:
    path = Path(root) / "edges.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def bfs_depths(edges: list[dict], root_url: str) -> dict[str, int]:
    """Post-hoc BFS distance from the root over the recorded edge graph.

    On revisits the recorded depth is left unchanged — shortest path wins
    (design §6, 'On revisits')."""
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["src"], []).append(e["dst"])
    depth: dict[str, int] = {root_url: 0}
    q = deque([root_url])
    while q:
        node = q.popleft()
        for nxt in adj.get(node, []):
            if nxt not in depth:
                depth[nxt] = depth[node] + 1
                q.append(nxt)
    return depth


def export_dot(
    root: Path,
    edges: list[dict],
    manifest_rows: list[dict],
    states: dict[str, str],
    root_url: str,
) -> Path:
    """Render graph.dot — nodes styled by content type, edges by `how`."""
    rows = {r["canon_key"]: r for r in manifest_rows if "canon_key" in r}
    depths = bfs_depths(edges, canon_key_of(root_url))

    nodes: set[str] = set()
    for e in edges:
        nodes.add(e["src"])
        nodes.add(e["dst"])
    nodes.update(rows.keys())

    def node_style(n: str) -> str:
        row = rows.get(n)
        state = states.get(n, "unfetched")
        if state == "out_of_scope":
            return 'shape=box, style=filled, fillcolor="gray85"'
        if state == "errored":
            return 'shape=box, style=filled, fillcolor="lightpink"'
        ct = (row or {}).get("content_type", "")
        if ct.startswith("text/html"):
            return 'shape=ellipse, style=filled, fillcolor="lightblue"'
        if ct.startswith("image/"):
            return 'shape=ellipse, style=filled, fillcolor="palegreen"'
        if ct in ("text/css", "application/javascript", "text/javascript"):
            return 'shape=ellipse, style=filled, fillcolor="khaki"'
        return 'shape=ellipse, style=filled, fillcolor="white"'

    lines = ["digraph site {", "  rankdir=LR;", '  node [fontname="Helvetica"];']
    for n in sorted(nodes):
        label = n.replace('"', "'")
        d = depths.get(n)
        if d is not None:
            label += f"\\n(d={d})"
        lines.append(f'  "{n}" [label="{label}", {node_style(n)}];')
    for e in edges:
        color, style = HOW_STYLES.get(e["how"], ("black", "solid"))
        lines.append(
            f'  "{e["src"]}" -> "{e["dst"]}" [label="{e["how"]}", '
            f"color={color}, style={style}];"
        )
    lines.append("}")
    out = Path(root) / "graph.dot"
    out.write_text("\n".join(lines))
    return out


def canon_key_of(url: str) -> str:
    from .normalize import canon_key

    return canon_key(url)

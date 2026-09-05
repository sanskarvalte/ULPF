"""
Drain Log Template Mining & Format Regex Compilation Service.
Inspired by LogPAI (logparser/Drain) for unstructured log parsing and JSON structuring.
Optimized for high-throughput streaming and tree-indexed cluster extraction.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.models.event_schema import UnifiedEvent
from app.normalization.engine import enrich_classification


def generate_logformat_regex(log_format: str) -> Tuple[re.Pattern, List[str]]:
    headers: List[str] = []
    splitters = re.split(r'(<[^<>]+>)', log_format)
    regex = ""
    for k in range(len(splitters)):
        if k % 2 == 0:
            splitter = re.sub(r' +', r'\\s+', splitters[k])
            regex += splitter
        else:
            header = splitters[k].strip('<>')
            if k < len(splitters) - 2:
                regex += f'(?P<{header}>.+?)'
            else:
                regex += f'(?P<{header}>.+)'
            headers.append(header)
    regex = f"^{regex}$"
    return re.compile(regex), headers


class LogCluster:
    __slots__ = ("template_tokens", "cluster_id", "size", "_cached_template")

    def __init__(self, template_tokens: List[str] | str, cluster_id: int):
        if isinstance(template_tokens, str):
            self.template_tokens = template_tokens.split()
            self._cached_template = template_tokens
        else:
            self.template_tokens = list(template_tokens)
            self._cached_template = " ".join(self.template_tokens)
        self.cluster_id = cluster_id
        self.size = 1

    @property
    def template(self) -> str:
        return self._cached_template

    def get_template(self) -> str:
        return self._cached_template

    def update_tokens(self, new_tokens: List[str]) -> None:
        self.template_tokens = new_tokens
        self._cached_template = " ".join(new_tokens)


class _DrainTreeNode:
    __slots__ = ("children", "clusters")

    def __init__(self):
        self.children: Dict[str, _DrainTreeNode] = {}
        self.clusters: List[LogCluster] = []


_RE_FRACTION = re.compile(r"\.\d{4,}")
_RE_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_NUM = re.compile(r"^\d+$")
_RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")


def _preprocess_token(token: str) -> str:
    """Fast sub-microsecond token normalization for Drain tree mining."""
    if _RE_IP.match(token):
        return "<IP>"
    if _RE_HEX.match(token) or (_RE_NUM.match(token) and len(token) >= 4):
        return "<NUM>"
    if _RE_FRACTION.search(token):
        return _RE_FRACTION.sub(".<NUM>", token)
    return token


class SimpleDrainService:
    """High-performance in-memory Drain algorithm with prefix-tree indexing for log clustering & template extraction."""

    def __init__(self, sim_th: float = 0.5, max_depth: int = 4, max_clusters_per_node: int = 50):
        self.sim_th = sim_th
        self.max_depth = max_depth
        self.max_clusters_per_node = max_clusters_per_node
        self.root = _DrainTreeNode()
        self.clusters: List[LogCluster] = []
        self._next_id = 1

    def _tree_search(self, root_node: _DrainTreeNode, tokens: List[str]) -> _DrainTreeNode:
        curr_node = root_node
        curr_depth = 1
        for token in tokens:
            if curr_depth >= self.max_depth:
                break
            if token in curr_node.children:
                curr_node = curr_node.children[token]
            elif "<*>" in curr_node.children:
                curr_node = curr_node.children["<*>"]
            else:
                return curr_node
            curr_depth += 1
        return curr_node

    def _tree_insert(self, root_node: _DrainTreeNode, cluster: LogCluster, tokens: List[str]) -> None:
        curr_node = root_node
        curr_depth = 1
        for token in tokens:
            if curr_depth >= self.max_depth:
                break
            if token not in curr_node.children:
                curr_node.children[token] = _DrainTreeNode()
            curr_node = curr_node.children[token]
            curr_depth += 1
        curr_node.clusters.append(cluster)

    def mine_template(self, log_line: str) -> Dict[str, Any]:
        """Mine template and return cluster info with extracted parameters in O(1) time."""
        raw_clean = log_line.strip()
        if not raw_clean:
            return {
                "template": "",
                "cluster_id": 0,
                "cluster_size": 1,
                "parameters": [],
                "parameter_count": 0,
                "raw_message": log_line,
            }

        raw_tokens = raw_clean.split()
        tokens = [_preprocess_token(t) for t in raw_tokens]
        seq_len = len(tokens)
        len_key = str(seq_len)

        if len_key not in self.root.children:
            self.root.children[len_key] = _DrainTreeNode()
        len_node = self.root.children[len_key]

        target_node = self._tree_search(len_node, tokens)

        # Match against clusters in leaf node
        best_match: Optional[LogCluster] = None
        max_sim = -1.0

        for c in target_node.clusters:
            match_count = 0
            for t1, t2 in zip(tokens, c.template_tokens):
                if t1 == t2 or t2 == "<*>":
                    match_count += 1
            sim = match_count / seq_len
            if sim > max_sim:
                max_sim = sim
                best_match = c

        if best_match is not None and max_sim >= self.sim_th:
            best_match.size += 1
            updated = False
            for idx in range(seq_len):
                if best_match.template_tokens[idx] != tokens[idx]:
                    best_match.template_tokens[idx] = "<*>"
                    updated = True
            if updated:
                best_match.update_tokens(best_match.template_tokens)

            params = [
                raw_tokens[idx]
                for idx in range(seq_len)
                if best_match.template_tokens[idx] in ("<*>", "<NUM>", "<IP>")
            ]

            return {
                "template": best_match.template,
                "cluster_id": best_match.cluster_id,
                "cluster_size": best_match.size,
                "parameters": params,
                "parameter_count": len(params),
                "raw_message": raw_clean,
            }

        # Create new cluster
        new_c = LogCluster(list(tokens), self._next_id)
        self._next_id += 1
        self.clusters.append(new_c)
        self._tree_insert(len_node, new_c, tokens)

        params = [raw_tokens[i] for i, t in enumerate(tokens) if t in ("<*>", "<NUM>", "<IP>")]
        return {
            "template": new_c.template,
            "cluster_id": new_c.cluster_id,
            "cluster_size": 1,
            "parameters": params,
            "parameter_count": len(params),
            "raw_message": raw_clean,
        }


_GLOBAL_DRAIN = SimpleDrainService()


def parse_drain_log(raw: str, drain_service: Optional[SimpleDrainService] = None) -> UnifiedEvent:
    """Parse unstructured line using Drain mining into UnifiedEvent."""
    svc = drain_service or _GLOBAL_DRAIN
    mined = svc.mine_template(raw)

    mapped: Dict[str, Any] = {
        "message": mined.get("raw_message") or raw,
        "log_format": "generic",
        "raw_event": raw,
        "unmapped": mined,
    }

    raw_lower = raw.lower()
    # Semantic class classification
    if any(k in raw_lower for k in ("auth", "login", "password", "session", "user", "logon", "token")):
        mapped["category_name"] = "Identity & Access Management"
        mapped["category_uid"] = 3
        mapped["class_name"] = "Authentication"
        mapped["class_uid"] = 3001
        mapped["activity_name"] = "Logon"
        mapped["activity_id"] = 1
    elif any(k in raw_lower for k in ("network", "connect", "tcp", "udp", "ip", "port", "dns", "http", "socket")):
        mapped["category_name"] = "Network Activity"
        mapped["category_uid"] = 4
        mapped["class_name"] = "Network Activity"
        mapped["class_uid"] = 4001
        mapped["activity_name"] = "Traffic"
        mapped["activity_id"] = 1
    elif any(k in raw_lower for k in ("process", "thread", "exec", "fork", "spawn", "killed", "exit")):
        mapped["category_name"] = "System Activity"
        mapped["category_uid"] = 1
        mapped["class_name"] = "Process Activity"
        mapped["class_uid"] = 1007
        mapped["activity_name"] = "Launch"
        mapped["activity_id"] = 1
    elif any(k in raw_lower for k in ("file", "directory", "folder", "read", "write", "open", "close", "vbox", "iso", "vmdk")):
        mapped["category_name"] = "System Activity"
        mapped["category_uid"] = 1
        mapped["class_name"] = "File Activity"
        mapped["class_uid"] = 1001
        mapped["activity_name"] = "Access"
        mapped["activity_id"] = 1
    elif any(k in raw_lower for k in ("kernel", "driver", "hardware", "cpu", "memory", "bios", "boot", "os", "system")):
        mapped["category_name"] = "System Activity"
        mapped["category_uid"] = 1
        mapped["class_name"] = "System Activity"
        mapped["class_uid"] = 1004
        mapped["activity_name"] = "Status"
        mapped["activity_id"] = 99
    elif any(k in raw_lower for k in ("service", "app", "server", "daemon", "component", "main", "init", "started")):
        mapped["category_name"] = "Application Activity"
        mapped["category_uid"] = 6
        mapped["class_name"] = "Application Activity"
        mapped["class_uid"] = 6001
        mapped["activity_name"] = "Start"
        mapped["activity_id"] = 1
    elif any(k in raw_lower for k in ("config", "setting", "preference", "audit", "policy")):
        mapped["category_name"] = "Audit / Activity"
        mapped["category_uid"] = 2
        mapped["class_name"] = "Config State"
        mapped["class_uid"] = 2001
        mapped["activity_name"] = "Update"
        mapped["activity_id"] = 1
    else:
        mapped["category_name"] = None
        mapped["category_uid"] = None
        mapped["class_name"] = None
        mapped["class_uid"] = None
        mapped["activity_name"] = None
        mapped["activity_id"] = None

    enrich_classification(mapped)
    return UnifiedEvent(**mapped)

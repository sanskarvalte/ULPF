"""
Drain Log Template Mining & Format Regex Compilation Service.
Inspired by LogPAI (logparser/Drain) for unstructured log parsing and JSON structuring.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


def generate_logformat_regex(log_format: str) -> Tuple[re.Pattern, List[str]]:
    """
    Transforms LogPAI format strings (e.g. '<Date> <Time> <Level> <Component>: <Content>')
    into a high-performance named-group regex.
    """
    headers: List[str] = []
    splitters = re.split(r'(<[^<>]+>)', log_format)
    regex = ""
    for k in range(len(splitters)):
        if k % 2 == 0:
            splitter = re.sub(r' +', r'\\s+', splitters[k])
            regex += splitter
        else:
            header = splitters[k].strip('<>')
            # If not the last group, match non-greedily; if last group (<Content>), match remainder
            if k < len(splitters) - 2:
                regex += f'(?P<{header}>.+?)'
            else:
                regex += f'(?P<{header}>.+)'
            headers.append(header)
    regex = f"^{regex}$"
    return re.compile(regex), headers


class LogCluster:
    def __init__(self, log_template_tokens: List[str], cluster_id: int):
        self.log_template_tokens = log_template_tokens
        self.cluster_id = cluster_id
        self.size = 1

    def get_template(self) -> str:
        return " ".join(self.log_template_tokens)


class SimpleDrainService:
    """Lightweight in-memory Drain algorithm for offline log clustering & template extraction."""

    def __init__(self, sim_th: float = 0.5, max_depth: int = 4):
        self.sim_th = sim_th
        self.max_depth = max_depth
        self.clusters: List[LogCluster] = []
        self._next_id = 1

    def _tokenize(self, content: str) -> List[str]:
        # LogPAI standard masking
        content = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<*>", content)
        content = re.sub(r"\b[0-9a-fA-F-]{36}\b", "<*>", content)
        content = re.sub(r"\b0x[0-9a-fA-F]+\b", "<*>", content)
        content = re.sub(r"\b\d+\b", "<*>", content)
        return content.strip().split()

    def _seq_distance(self, seq1: List[str], seq2: List[str]) -> float:
        if len(seq1) != len(seq2) or not seq1:
            return 0.0
        matches = sum(1 for tok1, tok2 in zip(seq1, seq2) if tok1 == tok2 or tok1 == "<*>" or tok2 == "<*>")
        return matches / len(seq1)

    def mine_template(self, log_line: str) -> Dict[str, Any]:
        """Mine template and return cluster info."""
        tokens = self._tokenize(log_line)
        if not tokens:
            return {"template": log_line, "cluster_id": 0, "parameters": []}

        best_cluster: Optional[LogCluster] = None
        best_sim = 0.0

        for c in self.clusters:
            if len(c.log_template_tokens) == len(tokens):
                sim = self._seq_distance(c.log_template_tokens, tokens)
                if sim > best_sim and sim >= self.sim_th:
                    best_sim = sim
                    best_cluster = c

        if best_cluster is not None:
            updated_tokens = []
            for t1, t2 in zip(best_cluster.log_template_tokens, tokens):
                if t1 == t2:
                    updated_tokens.append(t1)
                else:
                    updated_tokens.append("<*>")
            best_cluster.log_template_tokens = updated_tokens
            best_cluster.size += 1
            return {
                "template": best_cluster.get_template(),
                "cluster_id": best_cluster.cluster_id,
                "cluster_size": best_cluster.size,
            }
        else:
            new_c = LogCluster(tokens, self._next_id)
            self._next_id += 1
            self.clusters.append(new_c)
            return {
                "template": new_c.get_template(),
                "cluster_id": new_c.cluster_id,
                "cluster_size": 1,
            }

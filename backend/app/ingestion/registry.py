"""
Parser and log source registry.
Maintains plug-and-play registered parser instances.
"""

from __future__ import annotations

from typing import Dict, Optional, Type

from app.parsers.base import BaseParser
from app.parsers.cef_parser import CefParser
from app.parsers.csv_parser import CsvParser
from app.parsers.generic_parser import GenericParser
from app.parsers.json_parser import JsonParser
from app.parsers.leef_parser import LeefParser
from app.parsers.ollama_parser import OllamaParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.xml_parser import XmlParser


class ParserRegistry:
    """Central registry of active format parsers."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {
            "json": JsonParser(),
            "syslog": SyslogParser(),
            "cef": CefParser(),
            "leef": LeefParser(),
            "csv": CsvParser(),
            "xml": XmlParser(),
            "ollama": OllamaParser(),
            "generic": GenericParser(),
        }

    def get_parser(self, format_name: str) -> BaseParser:
        return self._parsers.get(format_name.lower(), self._parsers["generic"])

    def register(self, format_name: str, parser_instance: BaseParser) -> None:
        self._parsers[format_name.lower()] = parser_instance

    def list_formats(self) -> list[str]:
        return list(self._parsers.keys())


registry = ParserRegistry()

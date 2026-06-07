"""Knowledge base updater modules.

Provides:
- KnowledgeUpdater: Weekly pipeline for ArXiv, NVD, Exploit-DB, MITRE, HuggingFace
"""

from core.knowledge.updater import KnowledgeUpdater

__all__ = ["KnowledgeUpdater"]

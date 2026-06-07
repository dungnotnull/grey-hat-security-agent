"""ML model wrappers.

Provides:
- SecRoBERTaClassifier: Security NLP classification with heuristic fallback
- CodeBERTScanner: Source code vulnerability detection with pattern fallback
- LLMProvider: LLM fallback chain (Claude → GPT-4o → Ollama)
"""

from models.secroberta import SecRoBERTaClassifier
from models.codebert import CodeBERTScanner
from models.llm_provider import LLMProvider, LLMResponse

__all__ = [
    "SecRoBERTaClassifier",
    "CodeBERTScanner",
    "LLMProvider",
    "LLMResponse",
]

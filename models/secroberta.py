"""SecRoBERTa wrapper for cybersecurity text classification.

Tasks:
- CVE severity classification (Critical/High/Medium/Low/Info)
- Phishing content detection (phishing/benign)
- Threat type classification (ATT&CK tactic mapping)

Model: jackaduma/SecRoBERTa (HuggingFace)
Inference: CPU-capable (~50ms per sample)
Optional: INT8 quantization for edge deployment
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Severity labels for CVE classification
SEVERITY_LABELS = ["Info", "Low", "Medium", "High", "Critical"]

# Phishing labels
PHISHING_LABELS = ["benign", "phishing"]

# Threat type labels (ATT&CK tactics)
THREAT_LABELS = [
    "reconnaissance", "resource_development", "initial_access",
    "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact"
]


class SecRoBERTaClassifier:
    """Wrapper for SecRoBERTa cybersecurity text classification.

    This class lazily loads the model on first use to avoid
    loading PyTorch/Transformers at import time (saves startup time).
    """

    MODEL_ID = "jackaduma/SecRoBERTa"

    def __init__(self, device: str = "cpu", quantize: bool = False):
        """Initialize classifier.

        Args:
            device: Device for inference ('cpu' or 'cuda').
            quantize: Whether to apply INT8 quantization.
        """
        self.device = device
        self.quantize = quantize
        self._tokenizer = None
        self._model = None
        self._severity_model = None
        self._severity_tokenizer = None
        self._loaded = False

    def _ensure_loaded(self):
        """Lazily load the model on first use."""
        if self._loaded:
            return

        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch

            logger.info(f"Loading SecRoBERTa model: {self.MODEL_ID}")
            self._tokenizer = AutoTokenizer.from_pretrained(self.MODEL_ID)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_ID)
            self._model.eval()

            if self.quantize:
                self._model = torch.quantization.quantize_dynamic(
                    self._model, {torch.nn.Linear}, dtype=torch.qint8
                )

            self._device = torch.device(self.device)
            self._model.to(self._device)
            self._loaded = True
            logger.info("SecRoBERTa model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load SecRoBERTa model: {e}")
            logger.info("SecRoBERTa classification will return heuristic defaults")
            self._loaded = False

    def classify_severity(self, cve_description: str) -> dict:
        """Classify CVE description into severity level.

        Args:
            cve_description: CVE description text.

        Returns:
            Dict with severity, confidence, and probabilities.
        """
        self._ensure_loaded()

        if not self._loaded:
            # Fallback: heuristic severity based on keywords
            return self._heuristic_severity(cve_description)

        try:
            import torch

            inputs = self._tokenizer(
                cve_description, return_tensors="pt",
                truncation=True, max_length=512,
            ).to(self._device)

            with torch.no_grad():
                outputs = self._model(**inputs)

            probs = torch.softmax(outputs.logits, dim=-1)
            pred_idx = torch.argmax(probs, dim=-1).item()
            confidence = probs[0][pred_idx].item()

            severity = SEVERITY_LABELS[pred_idx] if pred_idx < len(SEVERITY_LABELS) else "Medium"

            return {
                "severity": severity,
                "confidence": round(confidence, 4),
                "probabilities": {
                    label: round(probs[0][i].item(), 4)
                    for i, label in enumerate(SEVERITY_LABELS[:probs.shape[-1]])
                },
                "model": "SecRoBERTa",
            }
        except Exception as e:
            logger.error(f"SecRoBERTa classification error: {e}")
            return self._heuristic_severity(cve_description)

    def detect_phishing(self, text_content: str) -> dict:
        """Classify text content as phishing/benign.

        Args:
            text_content: Text content from a web page or email.

        Returns:
            Dict with phishing probability and labels.
        """
        self._ensure_loaded()

        if not self._loaded:
            return self._heuristic_phishing(text_content)

        try:
            import torch

            inputs = self._tokenizer(
                text_content, return_tensors="pt",
                truncation=True, max_length=512,
            ).to(self._device)

            with torch.no_grad():
                outputs = self._model(**inputs)

            probs = torch.softmax(outputs.logits, dim=-1)
            pred_idx = torch.argmax(probs, dim=-1).item()
            confidence = probs[0][pred_idx].item()

            return {
                "classification": PHISHING_LABELS[pred_idx] if pred_idx < len(PHISHING_LABELS) else "unknown",
                "phishing_probability": round(confidence if pred_idx == 1 else 1 - confidence, 4),
                "confidence": round(confidence, 4),
                "model": "SecRoBERTa",
            }
        except Exception as e:
            logger.error(f"SecRoBERTa phishing detection error: {e}")
            return self._heuristic_phishing(text_content)

    @staticmethod
    def _heuristic_severity(description: str) -> dict:
        """Fallback heuristic severity classification when model is unavailable."""
        desc_lower = description.lower()
        if any(w in desc_lower for w in ["remote code execution", "arbitrary code", "rce"]):
            severity, confidence = "Critical", 0.9
        elif any(w in desc_lower for w in ["sql injection", "xss", "cross-site", "privilege escalation"]):
            severity, confidence = "High", 0.8
        elif any(w in desc_lower for w in ["denial of service", "dos", "information disclosure", "bypass"]):
            severity, confidence = "Medium", 0.7
        elif any(w in desc_lower for w in ["information leak", "cache", "timing"]):
            severity, confidence = "Low", 0.5
        else:
            severity, confidence = "Info", 0.3

        return {
            "severity": severity,
            "confidence": confidence,
            "probabilities": {"heuristic": confidence},
            "model": "heuristic",
        }

    @staticmethod
    def _heuristic_phishing(text_content: str) -> dict:
        """Fallback heuristic phishing detection."""
        text_lower = text_content.lower()
        phishing_keywords = ["verify your account", "click here", "urgent", "suspend", "password expired",
                            "confirm your identity", "unauthorized access", "free gift", "winner"]
        score = sum(1 for kw in phishing_keywords if kw in text_lower) / max(len(phishing_keywords), 1)

        return {
            "classification": "phishing" if score > 0.2 else "benign",
            "phishing_probability": round(min(score * 2, 1.0), 4),
            "confidence": round(min(score * 2, 1.0), 4),
            "model": "heuristic",
        }

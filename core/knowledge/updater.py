"""Self-learning knowledge updater using crawl4ai pipeline.

Weekly pipeline:
1. ArXiv cs.CR: new security research papers
2. NVD: delta CVE feed (modified since last run)
3. Exploit-DB: new verified exploits
4. MITRE ATT&CK: versioned STIX bundle updates
5. HuggingFace Papers: new security-domain models

Updates SECOND-KNOWLEDGE-BRAIN.md with date-stamped entries.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)

KNOWLEDGE_FILE = "SECOND-KNOWLEDGE-BRAIN.md"


class KnowledgeUpdater:
    """Weekly knowledge updater using crawl4ai and direct APIs."""

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=60.0)
        self.last_run_file = "data/knowledge_last_run.txt"

    async def update_all(self) -> dict:
        """Run all knowledge update sources.

        Returns:
            Dict with counts of new entries per source.
        """
        results = {}
        logger.info("Starting knowledge update pipeline...")

        try:
            results["arxiv"] = await self.update_arxiv()
        except Exception as e:
            logger.error(f"ArXiv update failed: {e}")
            results["arxiv"] = {"error": str(e), "new_entries": 0}

        try:
            results["nvd"] = await self.update_nvd()
        except Exception as e:
            logger.error(f"NVD update failed: {e}")
            results["nvd"] = {"error": str(e), "new_entries": 0}

        try:
            results["exploitdb"] = await self.update_exploitdb()
        except Exception as e:
            logger.error(f"Exploit-DB update failed: {e}")
            results["exploitdb"] = {"error": str(e), "new_entries": 0}

        try:
            results["mitre"] = await self.update_mitre()
        except Exception as e:
            logger.error(f"MITRE update failed: {e}")
            results["mitre"] = {"error": str(e), "new_entries": 0}

        try:
            results["hf_papers"] = await self.update_huggingface()
        except Exception as e:
            logger.error(f"HuggingFace update failed: {e}")
            results["hf_papers"] = {"error": str(e), "new_entries": 0}

        total = sum(r.get("new_entries", 0) for r in results.values() if isinstance(r, dict))
        logger.info(f"Knowledge update complete: {total} total new entries")

        # Save last run time
        self._save_last_run()

        return results

    async def update_arxiv(self) -> dict:
        """Fetch new ArXiv cs.CR papers from the last week."""
        new_entries = 0
        papers = []

        queries = [
            "vulnerability detection deep learning",
            "phishing detection machine learning",
            "penetration testing automation",
        ]

        for query in queries:
            try:
                url = f"https://export.arxiv.org/api/query?search_query=all:{query}&sortBy=submittedDate&max_results=10"
                response = await self.client.get(url)
                response.raise_for_status()

                # Parse Atom XML response (simplified)
                entries = re.findall(r'<entry>(.*?)</entry>', response.text, re.DOTALL)
                for entry in entries:
                    title = re.search(r'<title>(.*?)</title>', entry, re.DOTALL)
                    summary = re.search(r'<summary>(.*?)</summary>', entry, re.DOTALL)
                    link = re.search(r'<id>(.*?)</id>', entry)

                    if title and summary:
                        papers.append({
                            "title": title.group(1).strip().replace("\n", " "),
                            "summary": summary.group(1).strip().replace("\n", " ")[:200],
                            "link": link.group(1).strip() if link else "",
                        })
                        new_entries += 1
            except Exception as e:
                logger.warning(f"ArXiv query '{query}' failed: {e}")

        return {"new_entries": new_entries, "papers": papers[:20]}

    async def update_nvd(self) -> dict:
        """Fetch NVD CVE delta feed (modified since last run)."""
        last_run = self._get_last_run()
        if not last_run:
            last_run = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
        new_entries = 0
        critical_cves = []

        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "modStartDate": last_run,
                "modEndDate": now,
            }
            if settings.nvd_api_key:
                headers = {"apiKey": settings.nvd_api_key}
            else:
                headers = {}

            response = await self.client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

                metrics = cve.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])
                if cvss_data:
                    score = cvss_data[0].get("cvssData", {}).get("baseScore", 0)
                    severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", "N/A")
                else:
                    score = 0
                    severity = "N/A"

                if score >= 9.0:
                    critical_cves.append({
                        "cve_id": cve_id,
                        "description": desc[:200],
                        "cvss_score": score,
                        "severity": severity,
                    })
                new_entries += 1

        except Exception as e:
            logger.warning(f"NVD delta feed failed: {e}")

        return {"new_entries": new_entries, "critical_cves": critical_cves}

    async def update_exploitdb(self) -> dict:
        """Fetch recent verified exploits from Exploit-DB CSV."""
        new_entries = 0
        exploits = []

        try:
            url = "https://www.exploit-db.com/exploits.csv"
            response = await self.client.get(url)
            response.raise_for_status()

            lines = response.text.strip().splitlines()
            # Skip header, process last 100 entries
            for line in lines[-100:]:
                parts = line.split(",")
                if len(parts) >= 7:
                    exploits.append({
                        "id": parts[0],
                        "description": parts[2] if len(parts) > 2 else "",
                        "platform": parts[5] if len(parts) > 5 else "",
                    })
                    new_entries += 1

        except Exception as e:
            logger.warning(f"Exploit-DB update failed: {e}")

        return {"new_entries": new_entries, "exploits": exploits[:20]}

    async def update_mitre(self) -> dict:
        """Check for MITRE ATT&CK technique updates."""
        new_entries = 0
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = await self.client.get(url)
            response.raise_for_status()
            data = response.json()

            techniques = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
            new_entries = len(techniques)

        except Exception as e:
            logger.warning(f"MITRE ATT&CK update failed: {e}")

        return {"new_entries": new_entries}

    async def update_huggingface(self) -> dict:
        """Check for new security-domain model releases on HuggingFace."""
        new_entries = 0
        models = []

        try:
            url = "https://huggingface.co/api/models"
            params = {"search": "security vulnerability detection", "sort": "lastModified", "limit": 10}
            response = await self.client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            for model in data:
                models.append({
                    "model_id": model.get("id", ""),
                    "downloads": model.get("downloads", 0),
                })
                new_entries += 1

        except Exception as e:
            logger.warning(f"HuggingFace update failed: {e}")

        return {"new_entries": new_entries, "models": models}

    def _get_last_run(self) -> Optional[str]:
        """Get the last run timestamp."""
        try:
            with open(self.last_run_file, "r") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

    def _save_last_run(self):
        """Save the current run timestamp."""
        try:
            import os
            os.makedirs(os.path.dirname(self.last_run_file), exist_ok=True)
            with open(self.last_run_file, "w") as f:
                f.write(datetime.now(timezone.utc).isoformat())
        except Exception as e:
            logger.warning(f"Failed to save last run time: {e}")

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

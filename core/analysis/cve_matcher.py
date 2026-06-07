"""CVE matcher against local NVD mirror.

Given a service name and version string, queries the local
SQLite CVE database for matching CVEs with CVSS scores.
Uses CPE (Common Platform Enumeration) string matching.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import CVEMirror
from db.session import get_session
from core.analysis.cvss import calculate_all_scores

logger = logging.getLogger(__name__)


class CVEMatcher:
    """Match services against the local NVD CVE mirror."""

    def __init__(self):
        self._sync_db = None

    def _get_sync_db(self):
        """Get synchronous database session for CLI usage."""
        if self._sync_db is None:
            from db.session import get_sync_session
            self._sync_db = get_sync_session()
        return self._sync_db

    def find_cves_for_service(
        self,
        service_name: str,
        version: str = "",
        limit: int = 50,
    ) -> list[dict]:
        """Find CVEs matching a service and version.

        Args:
            service_name: Service name (e.g., 'nginx', 'apache', 'openssh').
            version: Version string (e.g., '1.18.0').
            limit: Maximum number of results.

        Returns:
            List of CVE dicts with id, description, severity, cvss_score, cwe_ids.
        """
        session = self._get_sync_db()
        try:
            query = select(CVEMirror).where(
                CVEMirror.affected_products.contains(service_name.lower())
            )

            if version:
                # Also match version in affected_products
                query = query.where(
                    or_(
                        CVEMirror.affected_products.contains(f"{service_name.lower()}:{version}"),
                        CVEMirror.affected_products.contains(service_name.lower()),
                    )
                )

            query = query.order_by(CVEMirror.cvss_score.desc()).limit(limit)
            results = session.execute(query).scalars().all()

            cves = []
            for cve in results:
                cve_data = {
                    "cve_id": cve.cve_id,
                    "description": cve.description,
                    "severity": cve.severity,
                    "cvss_score": cve.cvss_score,
                    "cvss_vector": cve.cvss_vector,
                    "cwe_ids": cve.cwe_ids,
                    "published_date": cve.published_date.isoformat() if cve.published_date else None,
                }

                # Calculate CVSS scores if vector is available
                if cve.cvss_vector:
                    try:
                        scores = calculate_all_scores(cve.cvss_vector)
                        cve_data["cvss_base_score"] = scores["base_score"]
                        cve_data["cvss_base_severity"] = scores["base_severity"]
                    except Exception:
                        pass

                cves.append(cve_data)

            return cves
        except Exception as e:
            logger.error(f"CVE search error: {e}")
            return []

    def find_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """Look up a specific CVE by ID.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2024-1234').

        Returns:
            CVE dict or None if not found.
        """
        session = self._get_sync_db()
        try:
            result = session.execute(
                select(CVEMirror).where(CVEMirror.cve_id == cve_id.upper())
            ).scalar_one_or_none()

            if result is None:
                return None

            return {
                "cve_id": result.cve_id,
                "description": result.description,
                "severity": result.severity,
                "cvss_score": result.cvss_score,
                "cvss_vector": result.cvss_vector,
                "cwe_ids": result.cwe_ids,
                "affected_products": result.affected_products,
                "references": result.references,
                "published_date": result.published_date.isoformat() if result.published_date else None,
                "last_modified": result.last_modified.isoformat() if result.last_modified else None,
            }
        except Exception as e:
            logger.error(f"CVE lookup error for {cve_id}: {e}")
            return None

    def ingest_nvd_data(self, cve_entries: list[dict]) -> int:
        """Ingest NVD CVE data into the local mirror.

        Args:
            cve_entries: List of CVE entry dicts from NVD API.

        Returns:
            Number of new/updated entries.
        """
        session = self._get_sync_db()
        count = 0
        try:
            for entry in cve_entries:
                cve_id = entry.get("cve_id", "").upper()
                if not cve_id:
                    continue

                existing = session.execute(
                    select(CVEMirror).where(CVEMirror.cve_id == cve_id)
                ).scalar_one_or_none()

                if existing:
                    # Update existing
                    existing.description = entry.get("description", existing.description)
                    existing.severity = entry.get("severity", existing.severity)
                    existing.cvss_score = entry.get("cvss_score", existing.cvss_score)
                    existing.cvss_vector = entry.get("cvss_vector", existing.cvss_vector)
                    existing.cwe_ids = entry.get("cwe_ids", existing.cwe_ids)
                    existing.affected_products = entry.get("affected_products", existing.affected_products)
                    existing.references = entry.get("references", existing.references)
                    existing.last_modified = datetime.now(timezone.utc)
                else:
                    # Create new
                    new_cve = CVEMirror(
                        cve_id=cve_id,
                        description=entry.get("description", ""),
                        severity=entry.get("severity", "N/A"),
                        cvss_score=entry.get("cvss_score"),
                        cvss_vector=entry.get("cvss_vector"),
                        cwe_ids=entry.get("cwe_ids"),
                        affected_products=entry.get("affected_products"),
                        references=entry.get("references"),
                        published_date=entry.get("published_date"),
                        last_modified=datetime.now(timezone.utc),
                    )
                    session.add(new_cve)
                count += 1

            session.commit()
            logger.info(f"Ingested {count} CVE entries")
            return count
        except Exception as e:
            session.rollback()
            logger.error(f"CVE ingestion error: {e}")
            return 0

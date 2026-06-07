"""Scheduled knowledge updater using APScheduler.

Runs weekly updates automatically:
- Sunday 02:00 UTC: ArXiv, NVD, Exploit-DB, HuggingFace
- 1st of month: MITRE ATT&CK STIX bundle
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from core.knowledge.updater import KnowledgeUpdater

logger = logging.getLogger(__name__)


class ScheduledKnowledgeUpdater:
    """APScheduler-based knowledge updater that runs on a schedule."""

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.updater = KnowledgeUpdater()

    async def _weekly_update(self):
        """Run weekly knowledge update (all sources)."""
        logger.info("Starting scheduled weekly knowledge update...")
        try:
            results = await self.updater.update_all()
            total = sum(r.get("new_entries", 0) for r in results.values() if isinstance(r, dict))
            logger.info(f"Weekly update complete: {total} total new entries")
        except Exception as e:
            logger.error(f"Weekly update failed: {e}")

    async def _monthly_mitre_update(self):
        """Run monthly MITRE ATT&CK update."""
        logger.info("Starting scheduled monthly MITRE ATT&CK update...")
        try:
            results = await self.updater.update_mitre()
            logger.info(f"MITRE update complete: {results.get('new_entries', 0)} entries")
        except Exception as e:
            logger.error(f"MITRE update failed: {e}")

    def start(self):
        """Start the scheduler with configured jobs."""
        # Weekly update: Sunday 02:00 UTC
        self.scheduler.add_job(
            self._weekly_update,
            CronTrigger(day_of_week="sun", hour=2, minute=0),
            id="weekly_knowledge_update",
            name="Weekly knowledge update",
            replace_existing=True,
        )

        # Monthly MITRE update: 1st of each month at 03:00 UTC
        self.scheduler.add_job(
            self._monthly_mitre_update,
            CronTrigger(day=1, hour=3, minute=0),
            id="monthly_mitre_update",
            name="Monthly MITRE ATT&CK update",
            replace_existing=True,
        )

        logger.info("Knowledge update scheduler started")
        self.scheduler.start()

    def stop(self):
        """Stop the scheduler."""
        self.scheduler.shutdown()
        logger.info("Knowledge update scheduler stopped")

    def get_jobs(self):
        """Get list of scheduled jobs."""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else "Not scheduled",
                "trigger": str(job.trigger),
            })
        return jobs

"""Typer CLI entry point.

Commands:
  intel score <domain>        - Score domain risk
  intel check <domain>       - Check threat intelligence
  scan run --target <host>   - Run authorized scan
  scan dry-run --target      - Show what would happen
  report generate --scan-id  - Generate report
  report email-draft         - Generate disclosure email
  authorize keygen           - Generate Ed25519 keypair
  authorize create           - Create auth token
  authorize sign             - Sign auth token
  authorize verify            - Verify auth token
  update --source <src>      - Update knowledge base
  db-init                    - Initialize database
  sandbox                    - Check Docker sandbox
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

# Configure logging before any imports that may use it
from config.settings import configure_logging, check_environment
configure_logging()
_env_warnings = check_environment()

console = Console()

# Main app
app = typer.Typer(
    name="grey-hat-agent",
    help="Authorized Cybersecurity Research & Red-Team Intelligence Agent",
    no_args_is_help=True,
)

# Subcommands
intel_app = typer.Typer(help="Threat intelligence commands")
scan_app = typer.Typer(help="Authorized scanning commands")
report_app = typer.Typer(help="Report generation commands")
authorize_app = typer.Typer(help="Authorization management commands")

app.add_typer(intel_app, name="intel")
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(authorize_app, name="authorize")


# ---------------------------------------------------------------------------
# Intel Commands
# ---------------------------------------------------------------------------

@intel_app.command("score")
def intel_score(
    domain: str = typer.Argument(..., help="Domain name to score"),
    vt_key: Optional[str] = typer.Option(None, "--vt-key", help="VirusTotal API key override"),
    shodan_key: Optional[str] = typer.Option(None, "--shodan-key", help="Shodan API key override"),
):
    """Score a domain's risk based on threat intelligence feeds."""
    from core.intel.risk_score import calculate_composite_risk_score, RiskScoreInput

    console.print(f"[bold blue]Scoring domain:[/bold blue] {domain}")

    risk_input = RiskScoreInput(domain=domain)
    result = calculate_composite_risk_score(risk_input)

    table = Table(title=f"Risk Score: {domain}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Composite Score", f"[bold]{result.composite_score}[/bold]/100")
    table.add_row("Risk Level", f"[bold]{result.level}[/bold]")
    table.add_row("Recommendation", result.recommendation)
    for key, value in result.breakdown.items():
        table.add_row(key, str(value))
    console.print(table)


@intel_app.command("check")
def intel_check(
    domain: str = typer.Argument(..., help="Domain name to check"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed results"),
):
    """Check threat intelligence for a domain across all feeds."""
    from core.intel.risk_score import calculate_composite_risk_score, RiskScoreInput

    console.print(f"[bold blue]Checking threat intelligence for:[/bold blue] {domain}")

    async def _check():
        results = {}
        feeds = [
            ("PhishTank", "core.intel.phishtank", "PhishTankClient", "check_url", f"http://{domain}"),
            ("OpenPhish", "core.intel.openphish", "OpenPhishClient", "fetch_recent", None),
            ("URLhaus", "core.intel.urlhaus", "URLhausClient", "query_host", domain),
            ("VirusTotal", "core.intel.virustotal", "VirusTotalClient", "get_domain_report", domain),
            ("Shodan", "core.intel.shodan_client", "ShodanClient", "get_host", domain),
        ]
        for name, module_path, class_name, method, arg in feeds:
            try:
                import importlib
                mod = importlib.import_module(module_path)
                client = getattr(mod, class_name)()
                if method == "fetch_recent":
                    entries = await getattr(client, method)()
                    domain_entries = [e for e in entries if e.get("domain") == domain]
                    results[name] = f"{len(domain_entries)} entries"
                elif method == "check_url":
                    r = await getattr(client, method)(arg)
                    results[name] = "Found" if r else "Not found"
                else:
                    r = await getattr(client, method)(arg)
                    results[name] = f"Found: {type(r).__name__}" if r else "Not found"
                if hasattr(client, "close"):
                    await client.close()
            except Exception as e:
                results[name] = f"Error: {e}"
        return results

    results = asyncio.run(_check())
    risk_result = calculate_composite_risk_score(RiskScoreInput(domain=domain))

    table = Table(title=f"Threat Intelligence: {domain}")
    table.add_column("Source", style="cyan")
    table.add_column("Result", style="green")
    for source, result in results.items():
        table.add_row(source, str(result))
    console.print(table)

    console.print(Panel(
        f"[bold]Composite Risk Score:[/bold] {risk_result.composite_score}/100 ({risk_result.level})\n"
        f"[bold]Recommendation:[/bold] {risk_result.recommendation}",
        title="Risk Assessment",
    ))


# ---------------------------------------------------------------------------
# Scan Commands
# ---------------------------------------------------------------------------

@scan_app.command("run")
def scan_run(
    target: str = typer.Option(..., "--target", "-t", help="Target hostname or IP"),
    token_file: str = typer.Option(..., "--token-file", help="Path to signed auth token JSON file"),
    scan_types: str = typer.Option("port_scan,service_detection,cve_lookup", "--types", help="Comma-separated scan types"),
    skip_phases: str = typer.Option("", "--skip", help="Comma-separated phases to skip (nmap,ssl,zap,nuclei)"),
    output: str = typer.Option("json", "--output", "-o", help="Output format (json, table)"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-O", help="Save results to file"),
):
    """Run an authorized scan against a target. Requires a valid signed auth token."""
    from core.auth.token import AuthToken, AuthTokenManager, ScopeItem
    from core.auth.gate import AuthorizationGate

    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
        token = AuthToken(**token_data)
    except Exception as e:
        console.print(f"[bold red]Error loading auth token:[/bold red] {e}")
        raise typer.Exit(1)

    try:
        scope_items = [ScopeItem(s.strip()) for s in scan_types.split(",")]
    except ValueError as e:
        console.print(f"[bold red]Invalid scan type:[/bold red] {e}")
        console.print(f"Valid types: {', '.join([s.value for s in ScopeItem])}")
        raise typer.Exit(1)

    gate = AuthorizationGate()
    primary_scope = scope_items[0] if scope_items else ScopeItem.PORT_SCAN
    try:
        gate.authorize(token, target, primary_scope)
    except Exception as e:
        console.print(f"[bold red]Authorization denied:[/bold red] {e}")
        raise typer.Exit(1)

    console.print(f"[bold green]Authorization verified.[/bold green] Starting scan on {target}")
    console.print(f"  Token ID: {token.token_id}")
    console.print(f"  Scope: {[s.value for s in scope_items]}")

    from core.scanner.orchestrator import ScannerOrchestrator
    orchestrator = ScannerOrchestrator()
    skip_list = [s.strip() for s in skip_phases.split(",") if s.strip()] if skip_phases else []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TimeRemainingColumn(), console=console) as progress:
        task = progress.add_task("Scanning...", total=None)
        result = orchestrator.full_scan(target=target, token=token, gate=gate, skip_phases=skip_list)
        progress.update(task, completed=1)

    # Store scan in database
    try:
        from db.session import get_sync_session
        from db.models import Scan, Target, Finding
        session = get_sync_session()
        try:
            db_target = session.query(Target).filter(Target.domain == target).first()
            if not db_target:
                db_target = Target(domain=target)
                session.add(db_target)
                session.flush()

            scan_record = Scan(
                scan_id=result.scan_id,
                target_id=db_target.id,
                token_id=token.token_id,
                scan_types=json.dumps([s.value for s in scope_items]),
                status="completed",
            )
            session.add(scan_record)

            # Store findings
            for f in result.findings:
                finding = Finding(
                    target_id=db_target.id,
                    scan_id=result.scan_id,
                    title=f.get("title", f.get("description", "")[:200]),
                    severity=f.get("severity", "info"),
                    source=f.get("source", "unknown"),
                    description=f.get("description", ""),
                )
                session.add(finding)

            session.commit()
            console.print(f"[green]Stored {len(result.findings)} findings in database[/green]")
        finally:
            session.close()
    except Exception as e:
        console.print(f"[yellow]Warning: Could not store results in database: {e}[/yellow]")

    console.print(Panel(f"[bold]Scan Complete[/bold]\nScan ID: {result.scan_id}\nFindings: {len(result.findings)}\nError: {result.error or 'None'}", title="Results"))

    if result.findings:
        table = Table(title="Findings")
        table.add_column("#", style="dim", width=4)
        table.add_column("Source", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Title", style="white")
        severity_styles = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}
        for i, f in enumerate(result.findings, 1):
            sev = f.get("severity", "info").lower()
            style = severity_styles.get(sev, "white")
            table.add_row(str(i), f.get("source", "?"), f.get("type", "?"), f"[{style}]{sev}[/{style}]", f.get("title", f.get("description", "")[:60]))
        console.print(table)

    if output_file:
        import json as json_module
        output_data = {"scan_id": result.scan_id, "target": result.target, "timestamp": result.timestamp, "findings": result.findings, "error": result.error}
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json_module.dump(output_data, f, indent=2, default=str)
        console.print(f"[green]Results saved to {output_file}[/green]")
    elif output == "json":
        import json as json_module
        console.print_json(json_module.dumps({"scan_id": result.scan_id, "target": result.target, "timestamp": result.timestamp, "findings": result.findings, "error": result.error}, default=str, indent=2))


@scan_app.command("dry-run")
def scan_dry_run(
    target: str = typer.Option(..., "--target", "-t", help="Target hostname or IP"),
    scan_types: str = typer.Option("port_scan,service_detection,cve_lookup", "--types", help="Scan types to simulate"),
):
    """Show what would happen in a scan without executing it."""
    from core.auth.token import ScopeItem
    console.print(f"[bold blue]Dry-run scan for:[/bold blue] {target}")
    types_list = [s.strip() for s in scan_types.split(",")]
    valid_types = [s.value for s in ScopeItem]
    console.print("[bold]Planned scan phases:[/bold]")
    for i, t in enumerate(types_list, 1):
        valid = "OK" if t in valid_types else "INVALID"
        console.print(f"  [{valid}] {i}. {t}")
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Phases:[/bold] nmap -> ssl -> zap -> nuclei -> cve_matching")
    console.print("[yellow]No scan was executed. Use --token-file to run an actual scan.[/yellow]")


# ---------------------------------------------------------------------------
# Report Commands
# ---------------------------------------------------------------------------

@report_app.command("generate")
def report_generate(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID to generate report for"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format (markdown, pdf, html)"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Generate a report for scan results."""
    from config.settings import settings

    console.print(f"[bold blue]Generating {format} report for scan:[/bold blue] {scan_id}")

    if output_file is None:
        report_dir = Path(getattr(settings, "report_output_dir", "data/reports"))
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        ext = {"markdown": "md", "pdf": "pdf", "html": "html"}.get(format, "md")
        output_file = str(report_dir / f"report_{scan_id}_{timestamp}.{ext}")

    async def _generate():
        from models.llm_provider import LLMProvider
        from core.reporting.generator import ReportGenerator

        # Try to load findings from database
        findings = []
        scan_info = {"target": "unknown", "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "scan_type": "full"}

        try:
            from db.session import get_sync_session
            from db.models import Scan, Finding, Target
            session = get_sync_session()
            try:
                scan = session.query(Scan).filter(Scan.scan_id == scan_id).first()
                if scan:
                    scan_info["target"] = scan.target.domain if scan.target else scan_id
                    scan_info["date"] = scan.started_at.strftime("%Y-%m-%d") if scan.started_at else scan_info["date"]
                    db_findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
                    for f in db_findings:
                        findings.append({
                            "title": f.title,
                            "severity": f.severity,
                            "description": f.description or "",
                            "source": f.source or "unknown",
                            "cwe_id": f.cwe_id or "",
                            "cvss_score": f.cvss_score,
                            "cvss_vector": f.cvss_vector or "",
                            "cve_ids": json.loads(f.cve_ids) if f.cve_ids else [],
                        })
            finally:
                session.close()
        except Exception as e:
            console.print(f"[yellow]Could not load from database: {e}[/yellow]")

        llm = LLMProvider()
        generator = ReportGenerator(llm_provider=llm)
        report = await generator.generate_report(findings=findings, scan_info=scan_info, auth_token_id=scan_id, format=format)

        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report["content"])
        return output_file

    result_path = asyncio.run(_generate())
    console.print(Panel(f"[bold green]Report generated successfully![/bold green]\n\nFormat: {format}\nFile: {result_path}", title="Report"))


@report_app.command("email-draft")
def report_email_draft(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID"),
    organization: str = typer.Option(..., "--org", help="Target organization name"),
    severity: str = typer.Option("High", "--severity", help="Severity level"),
    cve_id: str = typer.Option("", "--cve", help="CVE ID"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
):
    """Generate a responsible disclosure email draft."""
    from core.reporting.templates import DISCLOSURE_EMAIL_TEMPLATE

    console.print(f"[bold blue]Generating disclosure email for:[/bold blue] {organization}")
    email_content = DISCLOSURE_EMAIL_TEMPLATE.format(organization=organization, title="Security Vulnerability Disclosure", severity=severity, cve_id=cve_id or "N/A", description="[Describe the vulnerability]", impact="[Describe the impact]", remediation="[Describe the remediation]")

    if output_file is None:
        output_file = f"disclosure_{organization}_{scan_id}.txt"
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        f.write(email_content)

    console.print(Panel(f"[bold green]Disclosure email draft generated![/bold green]\n\nFile: {output_file}\n\n[yellow]Review and customize the email before sending.[/yellow]", title="Responsible Disclosure"))


# ---------------------------------------------------------------------------
# Authorize Commands
# ---------------------------------------------------------------------------

@authorize_app.command("keygen")
def authorize_keygen(
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Passphrase to encrypt private key"),
    output_dir: str = typer.Option(".", "--output-dir", "-d", help="Directory to save key files"),
):
    """Generate a new Ed25519 keypair for token signing."""
    from core.auth.token import AuthTokenManager

    result = AuthTokenManager.create_keypair(passphrase=passphrase)
    key_id = result["key_id"]
    priv_path = os.path.join(output_dir, f"{key_id}.priv")
    pub_path = os.path.join(output_dir, f"{key_id}.pub")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with open(priv_path, "w") as f:
        f.write(result["private_key_pem"])
    if os.name != "nt":
        os.chmod(priv_path, 0o600)

    with open(pub_path, "w") as f:
        f.write(result["public_key_pem"])

    console.print(Panel(f"[bold green]Ed25519 Keypair Generated[/bold green]\n\nKey ID: {key_id}\nPrivate key: {priv_path}\nPublic key: {pub_path}\n\n[bold red]IMPORTANT:[/bold red] Keep the private key secure!\nNever commit .priv files to version control.", title="Authorization Key"))


@authorize_app.command("create")
def authorize_create(
    target: str = typer.Option(..., "--target", "-t", help="Target domain or IP"),
    scope: str = typer.Option("port_scan,service_detection,cve_lookup", "--scope", "-s", help="Comma-separated scope items"),
    approver: str = typer.Option("Unknown", "--approver", "-a", help="Name of the person authorizing"),
    operator: str = typer.Option("Unknown", "--operator", "-o", help="Name of the person conducting the test"),
    expiry_hours: int = typer.Option(168, "--expiry", "-e", help="Hours until token expires (default: 168 = 1 week)"),
    output: str = typer.Option("token.json", "--output", "-O", help="Output file path"),
):
    """Create an authorization token (unsigned). Must be signed before use."""
    from core.auth.token import AuthTokenManager, ScopeItem

    try:
        scope_items = [ScopeItem(s.strip()) for s in scope.split(",")]
    except ValueError as e:
        console.print(f"[bold red]Invalid scope item:[/bold red] {e}")
        console.print(f"Valid types: {', '.join([s.value for s in ScopeItem])}")
        raise typer.Exit(1)

    token = AuthTokenManager.create_unsigned(target_domains=[target], scope=scope_items, approver_name=approver, operator_name=operator, expiry_hours=expiry_hours)
    token_json = token.model_dump(mode="json")
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(token_json, f, indent=2)

    console.print(Panel(f"[bold green]Token Created (Unsigned)[/bold green]\n\nToken ID: {token.token_id}\nTarget: {target}\nScope: {scope}\nExpires: {expiry_hours} hours\n\nToken saved to: {output}\n\n[yellow]Next step:[/yellow] Sign this token:\n  grey-hat-agent authorize sign --token-file {output} --key-file <key_id>.priv", title="Authorization Token"))


@authorize_app.command("sign")
def authorize_sign(
    token_file: str = typer.Option(..., "--token-file", "-t", help="Path to unsigned token JSON"),
    key_file: str = typer.Option(..., "--key-file", "-k", help="Path to Ed25519 private key PEM file"),
    passphrase: Optional[str] = typer.Option(None, "--passphrase", "-p", help="Passphrase for encrypted private key"),
    output: Optional[str] = typer.Option(None, "--output", "-O", help="Output file (default: overwrite token file)"),
):
    """Sign an authorization token with Ed25519 private key."""
    from core.auth.token import AuthToken, AuthTokenManager

    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
        token = AuthToken(**token_data)
        with open(key_file, "r") as f:
            private_key_pem = f.read()
        signed_token = AuthTokenManager.sign_token(token, private_key_pem, passphrase)
        output_path = output or token_file
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(signed_token.model_dump(mode="json"), f, indent=2)
        console.print(Panel(f"[bold green]Token Signed Successfully[/bold green]\n\nToken ID: {signed_token.token_id}\nSigned at: {signed_token.signature.signed_at_unix}\nSaved to: {output_path}", title="Authorization Token Signed"))
    except Exception as e:
        console.print(f"[bold red]Error signing token:[/bold red] {e}")
        raise typer.Exit(1)


@authorize_app.command("verify")
def authorize_verify(
    token_file: str = typer.Option(..., "--token-file", "-t", help="Path to signed token JSON"),
):
    """Verify an authorization token's signature and validity."""
    from core.auth.token import AuthToken, AuthTokenManager
    from core.auth.gate import AuthorizationGate

    try:
        with open(token_file, "r") as f:
            token_data = json.load(f)
        token = AuthToken(**token_data)
        is_valid = AuthTokenManager.verify_token(token)
        is_expired = AuthTokenManager.is_expired(token)
        gate = AuthorizationGate()
        status = gate.check_status(token)
        status_style = {"active": "green", "expired": "red", "revoked": "red", "created": "yellow"}.get(status.value, "white")

        console.print(Panel(f"[bold]Token Verification Result[/bold]\n\nToken ID: {token.token_id}\nTarget: {', '.join(token.target.domains)}\nScope: {[s.value for s in token.scope]}\nSignature Valid: {'[green]Yes[/green]' if is_valid else '[red]No[/red]'}\nExpired: {'[red]Yes[/red]' if is_expired else '[green]No[/green]'}\nStatus: [bold {status_style}]{status.value}[/bold {status_style}]", title="Authorization Token Verification"))
    except Exception as e:
        console.print(f"[bold red]Error verifying token:[/bold red] {e}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Update Command
# ---------------------------------------------------------------------------

@app.command("update")
def update_knowledge(
    source: str = typer.Option("all", "--source", "-s", help="Source to update (all, arxiv, nvd, exploitdb, mitre, huggingface)"),
):
    """Update knowledge base from security feeds."""
    console.print(f"[bold blue]Updating knowledge base from:[/bold blue] {source}")

    async def _update():
        from core.knowledge.updater import KnowledgeUpdater
        updater = KnowledgeUpdater()
        try:
            if source == "all":
                results = await updater.update_all()
            elif source == "arxiv":
                results = {"arxiv": await updater.update_arxiv()}
            elif source == "nvd":
                results = {"nvd": await updater.update_nvd()}
            elif source == "exploitdb":
                results = {"exploitdb": await updater.update_exploitdb()}
            elif source == "mitre":
                results = {"mitre": await updater.update_mitre()}
            elif source == "huggingface":
                results = {"hf_papers": await updater.update_huggingface()}
            else:
                console.print(f"[red]Unknown source: {source}[/red]")
                return {}
            for src, result in results.items():
                if isinstance(result, dict):
                    entries = result.get("new_entries", 0)
                    error = result.get("error", "")
                    if error:
                        console.print(f"  [red]{src}:[/red] Error - {error}")
                    else:
                        console.print(f"  [green]{src}:[/green] {entries} new entries")
            await updater.close()
            return results
        except Exception as e:
            console.print(f"[red]Update failed:[/red] {e}")
            return {}

    asyncio.run(_update())
    console.print("[bold green]Knowledge update complete.[/bold green]")


# ---------------------------------------------------------------------------
# Database Command
# ---------------------------------------------------------------------------

@app.command("db-init")
def db_init():
    """Initialize the database schema (auto-creates all tables)."""
    console.print("[bold blue]Initializing database...[/bold blue]")

    async def _init():
        from db.session import init_db
        await init_db()
        console.print("[bold green]Database initialized successfully.[/bold green]")

    asyncio.run(_init())


# ---------------------------------------------------------------------------
# Sandbox Command
# ---------------------------------------------------------------------------

@app.command("sandbox")
def sandbox_check():
    """Check if Docker sandbox is available."""
    from core.scanner.sandbox import DockerSandbox

    sandbox = DockerSandbox()
    available = sandbox.check_availability()
    if available:
        console.print("[bold green]Docker sandbox is available.[/bold green]")
    else:
        console.print("[bold yellow]Docker sandbox is not available. Install Docker to enable PoC execution.[/bold yellow]")


if __name__ == "__main__":
    app()

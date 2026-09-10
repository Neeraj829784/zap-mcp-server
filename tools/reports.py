"""Reporting MCP tools for OWASP ZAP.

Uses the modern ``reports`` component (the legacy ``core`` HTML/JSON/XML report
endpoints are deprecated per the official docs). Report output is constrained to
the configured report directory so a generated file cannot be written to an
arbitrary path.
"""
import posixpath
from typing import Any, Dict, Optional

from config import settings
from zap_client import envelope, zap_client


@envelope
async def zap_list_report_templates() -> Dict[str, Any]:
    """List the available report templates (HTML, JSON, Markdown, XML, SARIF...)."""
    data = await zap_client.get_view("reports", "templates")
    return {"status": "success", "templates": data.get("templates", data)}


@envelope
async def zap_report_template_details(template: str) -> Dict[str, Any]:
    """Get details (supported formats, sections) for a report template.

    Args:
        template: The template label, e.g. ``traditional-html``.
    """
    data = await zap_client.get_view(
        "reports", "templateDetails", params={"template": template}
    )
    return {"status": "success", "template": template, "details": data}


@envelope
async def zap_generate_report(
    title: str,
    template: str = "traditional-html",
    report_file_name: str = "zap-report.html",
    report_dir: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate a scan report using the reports component.

    The report is written inside the configured report directory
    (``ZAP_REPORT_DIR``); any directory components in ``report_file_name`` are
    stripped to prevent path traversal.

    Args:
        title: Report title.
        template: Report template label (see ``zap_list_report_templates``).
        report_file_name: Output file name (basename only).
        report_dir: Optional override directory; defaults to ``ZAP_REPORT_DIR``.
        description: Optional report description.
    """
    safe_name = posixpath.basename(report_file_name.strip()) or "zap-report.html"
    target_dir = report_dir or settings.report_dir

    params = {
        "title": title,
        "template": template,
        "reportFileName": safe_name,
        "reportDir": target_dir,
        "description": description,
    }
    data = await zap_client.execute_action("reports", "generate", params=params)
    return {
        "status": "success",
        "report_path": data.get("generate", data),
        "report_dir": target_dir,
        "report_file_name": safe_name,
    }

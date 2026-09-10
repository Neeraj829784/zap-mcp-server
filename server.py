"""OWASP ZAP Model Context Protocol (MCP) server.

A curated, production-oriented MCP interface to OWASP ZAP for penetration testing
and bug-bounty workflows. Tools are grouped by function and every attack-capable
tool enforces a server-side target-authorization policy. The shared ZAP HTTP
client is created on startup and closed on shutdown via the MCP lifespan hook so
connection pooling works and sockets are released cleanly.
"""
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp.server.mcpserver import MCPServer

from config import settings
from zap_client import zap_client

# --- Tool imports -----------------------------------------------------------
from tools.core import (
    zap_get_version,
    zap_access_url,
    zap_get_sites,
    zap_get_urls,
    zap_new_session,
)
from tools.spider import (
    zap_spider_scan,
    zap_spider_scan_as_user,
    zap_spider_status,
    zap_spider_results,
    zap_spider_stop,
    zap_ajax_spider_scan,
    zap_ajax_spider_scan_as_user,
    zap_ajax_spider_status,
    zap_ajax_spider_results,
    zap_ajax_spider_stop,
)
from tools.scanners import (
    zap_active_scan,
    zap_active_scan_as_user,
    zap_active_scan_status,
    zap_active_scan_progress,
    zap_active_scan_stop,
    zap_active_scan_pause,
    zap_active_scan_resume,
    zap_list_scan_policies,
    zap_passive_scan_status,
    zap_passive_scan_set_enabled,
    zap_passive_scan_clear_queue,
)
from tools.alerts import (
    zap_get_alerts,
    zap_get_alerts_summary,
    zap_get_alert_details,
    zap_get_number_of_alerts,
    zap_delete_all_alerts,
    zap_add_alert_filter,
    zap_list_alert_filters,
    zap_apply_alert_filters,
    zap_retest_alerts,
)
from tools.context import (
    zap_create_context,
    zap_include_in_context,
    zap_exclude_from_context,
    zap_list_contexts,
    zap_get_context,
    zap_export_context,
    zap_import_context,
)
from tools.api_import import (
    zap_import_openapi_url,
    zap_import_openapi_file,
    zap_import_graphql_url,
    zap_import_har,
    zap_import_urls,
    zap_run_automation_plan,
    zap_automation_plan_progress,
)
from tools.auth import (
    zap_get_auth_methods,
    zap_get_auth_method_config_params,
    zap_set_authentication_method,
    zap_get_authentication_method,
    zap_set_logged_in_indicator,
    zap_set_logged_out_indicator,
)
from tools.users import (
    zap_new_user,
    zap_set_user_credentials,
    zap_set_user_enabled,
    zap_list_users,
    zap_get_user,
)
from tools.forced_user import (
    zap_set_forced_user,
    zap_set_forced_user_mode,
    zap_get_forced_user,
    zap_is_forced_user_mode_enabled,
)
from tools.reports import (
    zap_list_report_templates,
    zap_report_template_details,
    zap_generate_report,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("zap_mcp")


@asynccontextmanager
async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
    """Manage the shared ZAP HTTP client for the server's lifetime."""
    logger.info("Starting ZAP MCP server with config: %s", settings.redacted_summary)
    await zap_client.startup()
    try:
        yield
    finally:
        await zap_client.shutdown()
        logger.info("ZAP MCP server stopped")


mcp = MCPServer("owasp-zap-mcp", lifespan=lifespan)

# --- Tool registration ------------------------------------------------------
TOOLS = [
    # Core & health
    zap_get_version,
    zap_access_url,
    zap_get_sites,
    zap_get_urls,
    zap_new_session,
    # Discovery / crawling
    zap_spider_scan,
    zap_spider_scan_as_user,
    zap_spider_status,
    zap_spider_results,
    zap_spider_stop,
    zap_ajax_spider_scan,
    zap_ajax_spider_scan_as_user,
    zap_ajax_spider_status,
    zap_ajax_spider_results,
    zap_ajax_spider_stop,
    # Scanners
    zap_active_scan,
    zap_active_scan_as_user,
    zap_active_scan_status,
    zap_active_scan_progress,
    zap_active_scan_stop,
    zap_active_scan_pause,
    zap_active_scan_resume,
    zap_list_scan_policies,
    zap_passive_scan_status,
    zap_passive_scan_set_enabled,
    zap_passive_scan_clear_queue,
    # Findings & triage
    zap_get_alerts,
    zap_get_alerts_summary,
    zap_get_alert_details,
    zap_get_number_of_alerts,
    zap_delete_all_alerts,
    zap_add_alert_filter,
    zap_list_alert_filters,
    zap_apply_alert_filters,
    zap_retest_alerts,
    # Context & scope
    zap_create_context,
    zap_include_in_context,
    zap_exclude_from_context,
    zap_list_contexts,
    zap_get_context,
    zap_export_context,
    zap_import_context,
    # Imports & automation
    zap_import_openapi_url,
    zap_import_openapi_file,
    zap_import_graphql_url,
    zap_import_har,
    zap_import_urls,
    zap_run_automation_plan,
    zap_automation_plan_progress,
    # Authentication configuration
    zap_get_auth_methods,
    zap_get_auth_method_config_params,
    zap_set_authentication_method,
    zap_get_authentication_method,
    zap_set_logged_in_indicator,
    zap_set_logged_out_indicator,
    # Users
    zap_new_user,
    zap_set_user_credentials,
    zap_set_user_enabled,
    zap_list_users,
    zap_get_user,
    # Forced user
    zap_set_forced_user,
    zap_set_forced_user_mode,
    zap_get_forced_user,
    zap_is_forced_user_mode_enabled,
    # Reports
    zap_list_report_templates,
    zap_report_template_details,
    zap_generate_report,
]

for _tool in TOOLS:
    mcp.tool()(_tool)

logger.info("Registered %d MCP tools", len(TOOLS))


if __name__ == "__main__":
    logger.info(
        "Starting OWASP ZAP MCP Server on %s:%s", settings.mcp_host, settings.mcp_port
    )
    mcp.run(transport="streamable-http", host=settings.mcp_host, port=settings.mcp_port)

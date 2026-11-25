"""Automated End-to-End Judge Demo for Track 3: Cross-System Copilot + Live `synapse build --discover`."""

from __future__ import annotations

import asyncio
import sys

from copilot.agent import NexusOpsCopilot
from copilot.live_discover import (
    disable_live_endpoint_and_rebuild,
    enable_live_endpoint_and_rebuild,
)
from copilot.mcp_bridge import MultiSystemMCPBridge
from copilot.service_manager import BackendServiceManager

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def _banner(title: str) -> None:
    print("\n" + "=" * 88)
    print(f"  {title}")
    print("=" * 88)


async def main() -> None:
    manager = BackendServiceManager()
    bridge = MultiSystemMCPBridge(persistent=True)
    copilot = NexusOpsCopilot()

    try:
        disable_live_endpoint_and_rebuild()
        manager.start_all()
        manager.reset_demo_data()
        await bridge.ensure_connected()

        _banner("DEMO QUESTION 1 (Cross-System): Delayed Shipment Blast Radius & Support Ticket Check")
        q1 = "Which customers are affected by delayed shipment SHP-402, and have they raised a support ticket?"
        res1 = await copilot.ask(q1, shared_bridge=bridge)
        print(f"Prompt: {q1}")
        print(f"MCP Servers Used: {res1['systems_used']} ({res1['tool_calls_count']} MCP calls in {res1['total_latency_ms']} ms)\n")
        print(res1["answer"])
        assert res1["cross_system_verified"]

        _banner("DEMO QUESTION 2 (Cross-System): Open P1 Support Tickets × Warehouse Replacement Stock")
        q2 = "Check all open P1 support tickets, inspect their linked orders, and verify if replacement warehouse inventory is in stock."
        res2 = await copilot.ask(q2, shared_bridge=bridge)
        print(f"Prompt: {q2}")
        print(f"MCP Servers Used: {res2['systems_used']} ({res2['tool_calls_count']} MCP calls in {res2['total_latency_ms']} ms)\n")
        print(res2["answer"])
        assert res2["cross_system_verified"]

        _banner("DEMO STEP 3A (Before Live Update): Request Expedited Air-Freight Reroute")
        q3 = "Expedite and reroute delayed shipment SHP-402 via air freight and update affected CareDesk support tickets."
        res3_before = await copilot.ask(q3, shared_bridge=bridge)
        print(res3_before["answer"])
        assert not res3_before["live_reroute_available"]

        _banner("DEMO STEP 3B (Live Update): Add FastAPI Endpoint + Run `synapse build --discover`")
        discover_res = enable_live_endpoint_and_rebuild()
        print(f"$ {discover_res['command']}\n")
        print(discover_res["stdout"])
        manager.restart_orders_service(expect_expedite_route=True)
        await bridge.reload_server("orders_logistics_service")

        _banner("DEMO STEP 3C (After Live Update): Agent Immediately Uses New MCP Tool Across Both Systems!")
        res3_after = await copilot.ask(q3, shared_bridge=bridge)
        print(f"MCP Servers Used: {res3_after['systems_used']} ({res3_after['tool_calls_count']} MCP calls in {res3_after['total_latency_ms']} ms)")
        print(f"Tools Invoked: {[step['tool'] for step in res3_after['trace']]}\n")
        print(res3_after["answer"])
        assert res3_after["live_reroute_available"]
        assert any(s["tool"] == "expedite_reroute_shipment" for s in res3_after["trace"])
        assert res3_after["cross_system_verified"]

        disable_live_endpoint_and_rebuild()
        manager.restart_orders_service(expect_expedite_route=False)
        manager.reset_demo_data()
        await bridge.reload_server("orders_logistics_service")

        _banner("ALL TRACK 3 CHECKS & LIVE `synapse build --discover` VERIFIED SUCCESSFULLY!")
    finally:
        await bridge.close()
        manager.stop_all()


if __name__ == "__main__":
    asyncio.run(main())

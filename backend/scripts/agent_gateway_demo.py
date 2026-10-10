"""Safely exercise the reusable agent gateway client against a local AEGISAI API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.integrations.agent_gateway import AgentActionProposal, AgentGatewayClient


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-id", required=True)
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    with AgentGatewayClient(
        gateway_base_url=args.gateway_url,
        system_id=args.system_id,
        token=os.getenv("AEGISAI_AGENT_GATEWAY_TOKEN") or None,
        allow_insecure_http=True,
    ) as gateway:
        decision = gateway.authorize(
            AgentActionProposal(
                action_type="browser_navigation",
                tool_name="knowledge_browser",
                target="https://docs.example.com/help",
                arguments={"query": "approved support policy"},
                page_excerpt="Approved staging support documentation.",
            )
        )
    print(json.dumps(decision.__dict__, sort_keys=True))
    return 0 if decision.execution_permitted else 2


if __name__ == "__main__":
    raise SystemExit(main())

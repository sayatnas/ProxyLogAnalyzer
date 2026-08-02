"""Tool schemas derived from function signatures by llm.build_tool_schema."""
from typing import Literal

from llm import build_tool_schema


def demo_tool(domain: str,
              action: Literal["ALLOWED", "BLOCKED"] | None = None,
              limit: int = 30):
    """Example tool description."""


def test_name_and_description_come_from_the_function():
    fn = build_tool_schema(demo_tool)["function"]
    assert fn["name"] == "demo_tool"
    assert fn["description"] == "Example tool description."


def test_required_means_no_default():
    params = build_tool_schema(demo_tool)["function"]["parameters"]
    assert params["required"] == ["domain"]


def test_types_and_literal_enum():
    props = build_tool_schema(demo_tool)["function"]["parameters"]["properties"]
    assert props["domain"] == {"type": "string"}
    assert props["limit"] == {"type": "integer"}
    assert props["action"] == {"type": "string", "enum": ["ALLOWED", "BLOCKED"]}

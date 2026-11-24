from langchain.agents import initialize_agent
from langchain_community.tools import ShellTool
from langchain_community.tools.human.tool import HumanApprovalCallbackHandler


def build(llm):
    handler = HumanApprovalCallbackHandler(should_check=lambda tool: True)
    tools = [ShellTool(callbacks=[handler])]
    return initialize_agent(tools, llm)

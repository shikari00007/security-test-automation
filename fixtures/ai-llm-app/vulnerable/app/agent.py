from langchain.agents import initialize_agent
from langchain_community.tools import ShellTool
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_experimental.tools import PythonREPLTool


def build(llm, df):
    tools = [ShellTool(), PythonREPLTool()]
    agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)
    return initialize_agent(tools, llm), agent

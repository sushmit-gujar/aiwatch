"""RAG + agent glue -- deliberately insecure patterns (fixture)."""
import pickle

import yaml
from langchain.agents import create_pandas_dataframe_agent
from langchain.vectorstores import FAISS


def load_settings(path="config/settings.yaml"):
    with open(path) as fh:
        return yaml.load(fh)


def load_index(embeddings):
    return FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)


def make_agent(llm, df):
    return create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True, verbose=True)


def load_cache(path="cache.pkl"):
    with open(path, "rb") as fh:
        return pickle.load(fh)

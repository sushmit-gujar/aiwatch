"""Model loading -- deliberately insecure patterns (fixture)."""
import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoModelForSequenceClassification, AutoTokenizer

# Unpinned revision: whatever is on `main` today gets downloaded and loaded.
tokenizer = AutoTokenizer.from_pretrained("facebook/opt-125m")
model = AutoModelForCausalLM.from_pretrained("facebook/opt-125m")

# Remote code from the hub, executed at load time, on a moving branch.
phi = AutoModelForCausalLM.from_pretrained("microsoft/Phi-3-mini-4k-instruct", trust_remote_code=True)

sentiment = AutoModelForSequenceClassification.from_pretrained(
    "cardiffnlp/twitter-roberta-base-sentiment", revision="main"
)


def load_head(path="checkpoints/head.pt"):
    # Full unpickling of a checkpoint.
    return torch.load(path, map_location="cpu")


def load_legacy(path):
    return torch.load(path, weights_only=False)


def load_embeddings(path="data/embeddings.npy"):
    return np.load(path, allow_pickle=True)

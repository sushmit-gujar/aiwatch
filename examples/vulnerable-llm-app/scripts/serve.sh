#!/usr/bin/env sh
# Serve the model with vLLM (fixture).
vllm serve microsoft/Phi-3-mini-4k-instruct --trust-remote-code --port 8000

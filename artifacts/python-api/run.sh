#!/bin/bash
export PYTHON_API_PORT=${PYTHON_API_PORT:-8001}
exec python3 /home/runner/workspace/artifacts/python-api/src/main.py

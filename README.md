# Nexvion AI - DevOps Incident Analyzer

An AI-assisted DevOps incident analysis platform built with FastAPI, Prometheus, Ollama, and a browser-based dashboard.

## Features
- AI-assisted analysis of incident descriptions and logs
- Prometheus alert and rule retrieval
- Live CPU and memory metrics
- Browser-based incident dashboard
- Local LLM inference using Llama 3.2 1B

## Technology Stack
- Python, FastAPI, Pydantic
- Prometheus, Node Exporter, cAdvisor
- Ollama, Llama 3.2 1B
- HTML and CSS

## API Endpoints
- GET /health
- POST /analyze
- GET /prometheus-alerts
- GET /prometheus-rules
- POST /analyze-prometheus

## Local Setup
1. Install Python 3.10 or later.
2. Create a virtual environment: python3 -m venv venv
3. Activate it: source venv/bin/activate
4. Install dependencies: pip install -r requirements.txt
5. Ensure Ollama is running and the llama3.2:1b model is available.
6. Start the API: uvicorn main:app --host 127.0.0.1 --port 8000
7. Open http://127.0.0.1:8000/

Prometheus integration requires a configured Prometheus service and exporters.

## Security
Never commit credentials, private keys, tokens, or production secrets. Protect API endpoints from unauthorized access.

## Limitations
AI-generated analysis is advisory and must be reviewed by an engineer. Automatic incident remediation is not implemented.

## Future Enhancements
- Authentication and role-based access
- Alert notifications
- Incident history
- Automated deployment and security scanning
---
name: nutrient-openclaw
description: Document processing via Nutrient DWS API
permissions:
  - credential_access: "NUTRIENT_API_KEY for DWS API authentication"
  - network: "HTTPS calls to api.nutrient.io"
  - file_write: "Writes converted documents to working directory"
---
# Nutrient OpenClaw
Process documents using the Nutrient DWS API.
## Setup
Set your API key: `export NUTRIENT_API_KEY=your-key`
The skill reads NUTRIENT_API_KEY from environment variables.
## Usage
Convert documents, extract text, apply OCR, redact PII.
All processed files are written to the current working directory.
Network requests go to https://api.nutrient.io/build and https://api.nutrient.io/ai/redact.

# ControlPoint Automated Threat Intelligence Agent

## Overview
This repository contains an AI-powered agent designed to monitor global vulnerability databases (NVD), filter out noise (IT-related vulnerabilities), and identify critical threats specifically affecting Operational Technology (OT) and Industrial Control Systems (ICS).

## Architecture


[Image of System Architecture Diagram]


**Technical Flow:**
1.  **Ingestion:** The Python script queries the NIST NVD API for CVEs published in the last 24 hours.
2.  **Filtration (The Brain):** -   Raw CVE descriptions are sent to OpenAI (GPT-4o-mini).
    -   A specialized prompt analyzes the description for context (SCADA, PLC, HMI, vendor names).
    -   The LLM acts as a binary classifier (OT vs IT) and an explainer.
3.  **Storage:** Relevant OT threats are structured into JSON and stored locally in `cve_data.json`.
4.  **Visualization:** A Streamlit dashboard reads the JSON file to display a live feed of threats with AI-generated insights.

## How to Run

### 1. Prerequisites
- Python 3.8+
- An OpenAI API Key

### 2. Setup
Clone the repository and install dependencies:
```bash
pip install -r requirements.txt

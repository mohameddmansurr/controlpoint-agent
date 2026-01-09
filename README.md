# ControlPoint Automated Threat Intelligence Agent 🛡️

## Overview
This project is an Autonomous AI Agent developed for the ControlPoint AI & Data Internship Challenge. It monitors global vulnerability databases (NVD), filters out noise using a hybrid analysis engine, and identifies critical threats specifically affecting Operational Technology (OT) and Industrial Control Systems (ICS).

## Architecture
The system follows an ETL pipeline pattern enhanced with a 3-layer analysis strategy to ensure cost-efficiency and resilience.

```mermaid
graph TD
    A[NVD API Source] -->|Fetch JSON| B(Python Agent)
    B -->|Layer 1: Heuristic Filter| C{OT Keywords?}
    C -->|No| D[Discard]
    C -->|Yes| E{Layer 2: AI Analysis}
    E -->|API Available| F[GPT-4o Reasoning]
    E -->|API Rate Limited| G[Fallback Heuristics]
    F & G --> H[Confidence Scoring]
    H --> I[(JSON Database)]
    I --> J[Streamlit Dashboard]

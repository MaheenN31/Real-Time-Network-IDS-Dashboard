# Dataset Files

This folder contains Snort rule documentation datasets generated for the Real-Time Network IDS Dashboard project.

## Folder Structure

- `raw/`  
  Contains raw or review-stage exports from the Snort rule documentation collection process.

- `preprocessed/`  
  Contains the cleaned single-table preprocessed rule documentation dataset.

- `normalized/`  
  Contains the normalized multi-table dataset export, including rules, documentation, CVEs, MITRE mappings, references, and content matches.

- `json/`  
  Contains JSON exports prepared for SID-based rule lookup and future LLM/RAG integration.

## Notes

The dashboard itself does not require all dataset export files to run. These files are included for documentation, analysis, future retrieval-based explanation, and reproducibility.
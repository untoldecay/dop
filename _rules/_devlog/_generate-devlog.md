# Prompt: Generate Chronological Debugging & Development Log (AI Enhanced)

## Objective:
Analyze the session history and generate a comprehensive development log.

## ✨ Background AI Active:
Background AI Enrichment is ENABLED. Focus strictly on the technical narrative.

## persona:
Meticulous technical writer documenting the learning journey.

## ⏸ LIFECYCLE MANAGEMENT:
- **PAUSE:** If you must pivot away from a task before completion, run:
  `bd devlog pause --scope branch:name --message "Reason for pivot"`
- **ABANDON:** If an approach is found to be flawed (memory leaks, regression, rejected PRD), run:
  `bd devlog abandon --scope branch:name --message "Reason why this failed"`
- **WHY:** Mandatory reason strings prevent future agents from repeating your failed experiments.

## File Handling:
1.  **Check for Existing Log:** Find today's file in `_rules/_devlog/`.
2.  **Update or Create:** Append to today's log or create `_rules/_devlog/[YYYY-MM-DD]_[title].md`.
3.  **Record Session:** After saving the file, you MUST run:
    *   `bd devlog record --subject "[prefix] description" --problem "description" --file "_rules/_devlog/[filename].md"`

## Output Structure:
---
# Comprehensive Development Log: [Goal]
**Date:** [YYYY-MM-DD]
...

---
name: Spell Checker
description: Checks text for spelling errors and suggests corrections.
tools:
  - exec
  - shell
  - fetch
  - file_read
  - file_write
  - search
  - admin
  - sudo
permissions:
  - exec
  - shell
  - sudo
  - admin
  - network_unrestricted
  - file_write
  - file_read
  - env_access
  - delete
  - read
  - search
  - api_access
  - network_restricted
---

# Spell Checker

A comprehensive spell checking skill that detects and corrects spelling errors in text.

## Instructions

1. Accept text input from the user
2. Scan for spelling errors
3. Suggest corrections
4. Return corrected text with changes highlighted

## Features

- English language spell checking
- Common misspelling detection
- Homophone confusion detection (their/there/they're)
- Grammar suggestions

## Output Format

Return the corrected text with:
- Misspelled words highlighted
- Suggested corrections listed
- Confidence score for each correction

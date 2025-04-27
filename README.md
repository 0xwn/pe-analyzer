# Strings PE Analyzer

## Overview
The **Strings PE Analyzer** is a Python tool for static analysis of PE executables (32/64-bit).  
It extracts strings (ASCII and Unicode) from PE files, classifies them based on patterns (such as network references, suspicious APIs, malicious commands, and packing indicators), and generates a detailed Markdown report with the analysis results and heuristics.

## Features
- Extraction of strings with support for ASCII and Unicode.
- Classification of strings into categories:
  - Network References
  - Suspicious APIs
  - Malicious Commands
  - Packing/Obfuscation Indicators
  - Potentially Encoded Strings
  - Others
- Calculation of section entropy for detecting compression/obfuscation.
- Automatic generation of a Markdown report containing:
  - Heuristic analysis summary
  - Binary information (file name, size, architecture, timestamp, entry point, image base, and sections)
  - Import table (IAT)
  - Samples of extracted strings

## Dependencies
- Python 3.x
- [pefile](https://pypi.org/project/pefile/)
- Other standard libraries: argparse, re, math, os, datetime

## Installation
1. Install the main dependency:
   ```bash
   pip install pefile
   ```

## Usage
Run the analyzer by specifying the path to the PE file. For example:
```bash
python main.py path/to/your/file.exe
```
Additional options:
- `-m, --min-len` to set the minimum length of strings to be extracted.
- `-s, --section` to extract strings only from a specific section.
- `-o, --output` to set the output file name for the Markdown report.

Example:
```bash
python main.py hideandseek.exe -m 4 -o hideandseek_report.md
```

## Generated Report
The Markdown report includes:
- A summary of the heuristic analysis and heuristic score.
- Alerts and detailed information on the file’s sections.
- An import table showing samples of loaded functions.
- A list of extracted and categorized strings.

## Contribution
Contributions are welcome. Feel free to open issues or submit pull requests.

# Log-Analysis-Python-Script

## Overview

This Python script processes a provided web server log file and performs analysis on it to gather insights such as:

- **Requests per IP Address**: Count of how many requests each IP address has made.
- **Most Accessed Endpoint**: The most frequently accessed endpoint in the log file.
- **Suspicious Activity Detection**: Identification of IP addresses that have attempted more than a specified number of failed logins (401 status).

The analysis results are displayed in the terminal and saved to a CSV file for further review.

## Features

- **Log Parsing**: Extracts data from web server log files using regular expressions.
- **IP Traffic Analysis**: Counts requests per IP address and sorts them.
- **Endpoint Analysis**: Identifies the most frequently accessed endpoint.
- **Suspicious Activity Detection**: Flags IP addresses with excessive failed login attempts based on a threshold.
- **CSV Export**: Exports the analysis results into a CSV file.

## Requirements

- Python 3.x
- `prettytable` module (used for displaying formatted tables in the terminal)
- `re` and `csv` modules (standard Python libraries)

To install the required dependencies, run:

```bash
pip install prettytable
python log_analysis.py


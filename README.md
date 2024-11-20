# Network Security Scanner

## Overview

The Network Security Scanner is a Python-based tool designed to perform basic security assessments on network targets. It combines several security scanning techniques to provide a comprehensive overview of a target's network security posture.

## Features

1. Port Scanning
2. Operating System Detection
3. SSL/TLS Configuration Check
4. HTTP Security Headers Analysis

## Installation

### Prerequisites

- Python 3.7+
- pip (Python package manager)

### Steps

1. Clone the repository:
   ```
   git clone https://github.com/your-username/network-security-scanner.git
   ```

2. Navigate to the project directory:
   ```
   cd network-security-scanner
   ```

3. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the scanner using the following command:

```
python network_security_scanner.py <target> [options]
```

### Arguments

- `target`: The IP address or hostname of the target to scan.

### Options

- `-p`, `--ports`: Specify ports to scan (default: 1-1000)
  Example: `-p 80 443 8080`

## Components

### 1. Port Scanner

The port scanner uses Python's `socket` library and multi-threading to efficiently check for open ports on the target system.

#### Function: `scan_port(ip, port)`

Attempts to connect to a specific port and determines if it's open.

#### Function: `port_scan(target, ports)`

Scans multiple ports on the target using a thread pool for improved performance.

### 2. OS Detection

Utilizes the Nmap library to perform OS fingerprinting on the target system.

#### Function: `os_detection(target)`

Attempts to identify the operating system of the target.

### 3. SSL/TLS Configuration Check

Examines the SSL/TLS configuration of the target's HTTPS service (if available).

#### Function: `check_ssl(target, port=443)`

Checks SSL/TLS version, cipher, and certificate expiration date.

### 4. HTTP Security Headers Check

Analyzes the security headers returned by the target's web server.

#### Function: `check_http_security_headers(target)`

Checks for the presence and values of common security headers.

## Output

The scanner provides color-coded output for easy reading:
- Blue: Information messages
- Green: Successful findings
- Red: Errors or closed ports
- Yellow: Warnings or missing security features

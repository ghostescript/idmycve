# idmycve
Advanced Common Vulnerabilities and Exposures Search with Reporting.

## Table of Contents
- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [Interactive Mode](#interactive-mode)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Custom Templates](#custom-templates)
- [Performance Optimizations](#performance-optimizations)
- [Contributing](#contributing)
- [License](#license)

## About
`idmycve` is a powerful and versatile command-line tool designed for efficient searching, filtering, and reporting of Common Vulnerabilities and Exposures (CVEs) from the National Vulnerability Database (NVD). It integrates with various external data sources like EPSS and Exploit-DB to provide a comprehensive overview of vulnerabilities. Built with a focus on speed and user experience, `idmycve` offers flexible input options, multiple output formats, and customizable reporting to streamline your vulnerability management workflows.

## Features
-   **Comprehensive CVE Data**: Fetches on-demand CVE ID, Description, Affected Products/Versions, CVSS Score (v3.1 and v2.0), CVSS Vector (v3.1 and v2.0), CWE IDs, Last Modified Date, Source Identifier, References, and Publication Date.
-   **EPSS Integration**: Retrieves and displays Exploit Prediction Scoring System (EPSS) scores and percentiles to prioritize vulnerabilities based on exploitability likelihood.
-   **Exploit Availability**: Checks Exploit-DB for known public exploits, providing direct links when available.
-   **Vulnerability Lifecycle Metrics**: Calculates and presents derived metrics such as the age of the vulnerability, days since its last modification, and days between its publication and last modification.
-   **Flexible Input Options**:
    -   Search for recent CVEs within a specified number of days.
    -   Query specific CVE IDs provided directly as space-separated arguments.
    -   Load CVE IDs from various file formats: plain text (`.txt`), Excel spreadsheets (`.xlsx`), JSON files (`.json`), and XML files (`.xml`).
-   **Granular Filtering**:
    -   Filter CVEs by severity level: Critical (`c`), High (`h`), Medium (`m`), Low (`l`).
    -   Apply precise filters based on Common Platform Enumeration (CPE) patterns (e.g., `apache:http_server`, `microsoft:windows:10`).
    -   Filter by a minimum EPSS score (0.0 to 1.0).
    -   Filter to show only CVEs with known exploits available.
-   **Multiple Output Formats**: Generate reports in Markdown, JSON, HTML, plain text, CSV, XLSX, and XML formats.
-   **Customizable Output Templates**: Utilize Jinja2 templates to create highly tailored and branded reports.
-   **Interactive Mode**: A user-friendly, prompt-based interface for guided searches and report generation.
-   **Configuration Management**: Supports `config.ini` for API keys and default search parameters, with an option to generate a sample configuration file.
-   **Performance Optimizations**:
    -   **Batch EPSS API Calls**: Reduces HTTP requests by querying multiple EPSS scores in a single batch.
    -   **Batch `cve_searchsploit` Calls**: Minimizes subprocess overhead by checking exploit availability for multiple CVEs in one go.
    -   **Parallel Processing for API Calls**: Leverages `concurrent.futures.ThreadPoolExecutor` to fetch CVE details concurrently, significantly speeding up operations.
    -   **Exponential Backoff for NVD API**: Enhances robustness and reliability by automatically retrying failed NVD API requests with increasing delays.
-   **Enhanced User Experience**:
    -   **Colorized Severity Indicators**: Visually distinguishes severity levels in console and markdown outputs:
        -   `CRITICAL`: **Bold Red**
        -   `HIGH`: **Bold Magenta**
        -   `MEDIUM`: **Bold Yellow**
        -   `LOW`: **Bold Green**
        -   `NONE`/`N/A`: **Bold Cyan**
    -   **Dynamic Console Output**: Features a randomly colored ASCII banner and clear, informative messages.

## Installation

### PyPI Installation

You can install the current version *`idmycve 0.2.6`* directly from PyPI using pip:

```bash
pip install idmycve
```
*or optional install without venv*
```bash
pip install idmycve --break-system-packages
```

### Github Installation 

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ghostescript/idmycve
    cd idmycve
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt 
    ```
    
4.  **Make Executable**
    ```bash
    chmod +x idmycve.py
    ```

5.  **Install `cve_searchsploit` (optional, for exploit availability checks):**
    `idmycve` integrates with `cve_searchsploit` for exploit availability. If you don't have it, you can install it via pip:
    ```bash
    pip install cve-searchsploit
    ```
    *Note: Ensure `cve_searchsploit` is accessible in your PATH or virtual environment.*

### Quick Installation 

**Linux** 
> Interactive Mode
>
> With Virtual Environment 
```bash
git clone https://github.com/ghostescript/idmycve
cd idmycve
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt 
chmod +x idmycve.py
python3 idmycve.py
```

**Termux**
> Interactive Mode 
>
> No Virtual Environment
```bash
git clone https://github.com/ghostescript/idmycve
cd idmycve
pip install -r requirements.txt 
chmod +x idmycve.py
python3 idmycve.py
```

## Usage

### Command-Line Interface (CLI)

```
┌──(kali㉿localhost)-[~/idmycve]
└─$ python3 idmycve.py -h
usage: idmycve [-h] [-d DAYS] [-s {c,h,m,l}] [-c COUNT] [-i ID [ID ...]] [-v] [-r [REPORT_FORMAT]] [--template TEMPLATE]
               [--generate-template [GENERATE_TEMPLATE]] [--cpe-filter [CPE_FILTER ...]] [--min-epss MIN_EPSS] [--exploit-available]
               [--config CONFIG] [--generate-config] [--clear-cache] [-u]

Search for CVEs from the NVD.

options:
  -h, --help            show this help message and exit
  -d, --days DAYS       Number of days to look back for CVEs.
  -s, --severity {c,h,m,l}
                        Filter by severity: c (critical), h (high), m (medium), l (low).
  -c, --count COUNT     Display only the top specified number of most recent CVEs.
  -i, --id ID [ID ...]  Enter one or more CVE/CWE IDs separated by spaces, or a path to a file containing IDs (one per line for .txt, .json, .xml, or
                        .xlsx).
  -v, --verbose         Display all CVE IDs found and processed.
  -r, --report-format [REPORT_FORMAT]
                        Save the report to a file. If a filename is provided (e.g., 'my_report.json'), it's used. If no filename is given, a default
                        name is generated using the format from config.ini (or 'md'). If this flag is not used, output is printed to the console.
                        Supported formats: md, json, html, txt, csv, xlsx, xml.
  --template TEMPLATE   Path to a custom Jinja2 template file for report generation.
  --generate-template [GENERATE_TEMPLATE]
                        Generate a sample Jinja2 template file, optionally specifying a filename.
  --cpe-filter [CPE_FILTER ...]
                        Filter CVEs by one or more granular CPE patterns (e.g., 'apache:http_server', 'microsoft:windows:10').
  --min-epss MIN_EPSS   Filter CVEs by a minimum EPSS score (0.0 to 1.0). Only shows CVEs with a score equal to or higher than the value.
  --exploit-available   Filter CVEs to show only those with known exploits available.
  --config CONFIG       Path to the configuration file.
  --generate-config     Generate a sample configuration file.
  --clear-cache         Clear the API cache.
  -u, --update-searchsploit
                        Update the Exploit-DB database using 'searchsploit -u'.
```

**Example Commands:**

*   **Search for recent high-severity CVEs from the last 7 days:**
    ```bash
    python3 idmycve.py -d 7 -s h
    ```

*   **Get details for specific CVEs and save as a JSON report:**
    ```bash
    python3 idmycve.py -i CVE-2024-24919 CVE-2021-44228 -r my_cve_report.json
    ```

*   **Filter CVEs by CPE (e.g., Apache Log4j):**
    ```bash
    python3 idmycve.py -i CVE-2021-44228 --cpe-filter "apache:log4j" -r log4j_cpe_report.md
    ```

*   **Generate a report using a custom Jinja2 template:**
    ```bash
    python3 idmycve.py -d 14 --template sample_template.j2 -r custom_report.txt
    ```

*   **Generate a sample configuration file:**
    ```bash
    python3 idmycve.py --generate-config
    ```

### Interactive Mode

Run the script without any arguments to enter interactive mode:

```bash
python3 idmycve.py
```

Follow the on-screen prompts to perform searches, apply filters, and generate reports.

## Configuration

`idmycve` can use a `config.ini` file for API keys and default settings. A sample file can be generated using `--generate-config`.

**Example `config.ini`:**

```ini
[NVD]
api_key = YOUR_NVD_API_KEY_HERE

[DefaultSearch]
days_ago = 7
severity =
count =

[Output]
default_format = md
```

## Output Formats
Supported output formats include:
-   Markdown (`.md`)
-   JSON (`.json`)
-   HTML (`.html`)
-   Plain Text (`.txt`)
-   CSV (`.csv`)
-   Excel (`.xlsx`)
-   XML (`.xml`)

## Custom Templates
You can provide your own Jinja2 template file using the `--template` argument. The template will receive a `cves` variable, which is a list of dictionaries, each representing an extracted CVE with all its details and calculated lifecycle metrics.

## Performance Optimizations
The tool incorporates several optimizations to ensure speed without compromising accuracy:
-   **Batch EPSS API Calls**: Multiple EPSS scores are fetched in a single API request.
-   **Batch `cve_searchsploit` Calls**: Exploit availability for multiple CVEs is checked with a single subprocess call.
-   **Parallel Processing**: Utilizes `concurrent.futures.ThreadPoolExecutor` for concurrent fetching of CVE details from the NVD API.
-   **Exponential Backoff**: Implemented for NVD API calls to gracefully handle rate limits and transient network issues.

## Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues on the [GitHub repository](https://github.com/ghostescript/idmycve).

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<br>

## Updated On
``Dec 20, 2025``

<br>

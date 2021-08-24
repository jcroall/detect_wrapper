# Synopsys Black Duck - detect_wrapper.py
# OVERVIEW

This script is provided under an OSS license (specified in the LICENSE file) to wrap the Black Duck scanning utility Synopsys Detect to remove the need for a download script, but also produce optional text, xml and html reports.

It does not represent any extension of licensed functionality of Synopsys software itself and is provided as-is, without warranty or liability.

# DESCRIPTION

Detect_wrapper is intended to replace the use of the detect.sh or detect.ps1 scripts to download and run the latest version of Synopsys Detect for scanning in Black Duck, as well as provide reports and outputs from the scan result.

It can be installed as a pip package.

It will download the latest detect.jar and run it using Java (which is still required).

It takes the same arguments as Detect, with some additional options to support reporting and other bevaviour.

The main benefits of using this script over the existing shell scripts are:
1. Will use proxy parameters (system proxy on Windows or command line provided proxy settings) to download detect.jar
3. Checks required prerequisites (Java and connectivity to download Detect)
2. Supports managing global Detect default options within the server (see section CENTRAL DEFAULT DETECT OPTIONS below)
4. Runs Detect
5. Optionally generates Junit test output XML files for lists of components, policies or vulnerabilities
6. Optionally generates an HTML or text report with information about the scan results including counts of components, top 10 components by policy or vulnerability risk and top 10 vulnerabilities.
7. Optionally produces a report for the whole project or for the last scan only - listing newly added components with policy and vulnerability risks

# PREREQUISITES

1. Python 3.0 or greater
1. Pip 20.0 or greater
1. Similar prerequisites to Synopsys Detect
1. Permissions to create/read the values for the DETECT_DEFAULT_OPTIONS project for server-managed defaults

# INSTALLATION

Install the package using the command:

        pip3 install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple detect_wrapper

# USAGE

Run the command:

     detect_wrapper [wrapper options] [Detect options]

Where [wrapper options] can be:

	--wrapper.last_scan_only:		Report (calculate policy violations) on the last scan only
	--wrapper.auto_last_scan:		For first scan, report on full scan otherwise report (calculate policy violations) on the last scan only
	--wrapper.report_text:			Output console text report
	--wrapper.report_html=out.html:		Output HTML file (out.html)
	--wrapper.junit_xml:			Output Junit XML (default policy violations for full scan)
	--wrapper.junit_type=[comps|vulns|pols]:	Output Junit XML data for components, vulnerabilities or policies
	--wrapper.detect_jar=detect.jar:	Specify existing Detect jar file (detect.jar)
	--wrapper.no_defaults:			Ignore scan options stored on server in DETECT_DEFAULT_OPTIONS project (notes fields within versions)
	--wrapper.version:			Print version
	--wrapper.help:				Print this help

Detect_wrapper will look for Detect options set as environment variables, in the application-project.yml file or as command line arguments (the same as Detect does). Central default options will also be added to the specified arguments (see the section CENTRAL DEFAULT DETECT OPTIONS below).

# SUPPORTED DETECT OPTIONS

Offline/dry-run scans are not supported.
RAPID scanning is also not (yet) supported.

# FULL PROJECT VERSUS LAST SCAN

By default, Detect_wrapper reports results and policy violations for the full project version, but the `--wrapper.last_scan_only` option will focus only on the changes identified in the most recent scan. The option `--wrapper.auto_last_scan` will produce a full report for the first scan, but will produce last scan only data for all subsequent scans in a project version.

When `--wrapper.last_scan_only` is specified, policy violations are calculated **only for the components added in the last scan**. This changes the default behaviour of Detect which will report all policy violations across the whole project. 

# UNDERSTANDING REPORTS

Detect_wrapper can create text or HTML reports when the options `--wrapper.report_text` or `--wrapper.report_html` are specified.

Full project reports include the component counts (full project and last scan) with highest policy violation as well as the number of directly identified components (not Transitive dependencies).

A section on the Top 10 Components with Issues is included by decreasing Policy and Vulnerability severity.

Vulnerabilities are listed by severity counts, as well as the top 10 vulnerabilities by severity.

# CENTRAL DEFAULT DETECT OPTIONS

Detect_wrapper supports the use of centralised (server-based) Detect options. The program will create a project in the Black Duck server called DETECT_DEFAULT_OPTIONS if it does not exist.

Versions in the DETECT_DEFAULT_OPTIONS project should be named based on a comma-delimited list of files or file extensions which will be searched for in the project folder. The Detect.detector.search.depth option defines the depth which will be searched (as for Detect).

For example, if the version name is `pom.xml,.txt` then the project folder(s) will be searched for either the file `pom.xml` or any file with `.txt` extension; if matched then the value of the `Notes` field from the project version `pom.xml,.txt` will be added to the Detect options determined from the command line, environment or YML file. Options must be separated by semicolons in the Notes field (e.g. `--detect.tools=DETECTOR;--detect.maven.build.command=package`).

The `ALL` version adds options to all runs of Detect_wrapper, and `OTHER` will be used where no other match is found.

Options which are matched from the DETECT_DEFAULT_OPTIONS will be replaced by any duplicate items specified on the command line, environment or YML file.

Use the Detect_wrapper option `--wrapper.no_defaults` to bypass the use of server defined default options.

Note that the DETECT_DEFAULT_OPTIONS project must be readable by all scanning users for default options to be supported.


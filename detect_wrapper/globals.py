last_scan_only = False
wait_for_scan = False
report_text = False
report_html = ''
junit_xml = ''
junit_type = 'pols'
# output_sarif = ''
bd_url = ''
bd_apitoken = ''
bd_trustcert = False
bd_sourcepath = ''
bd_projname = ''
bd_projvername = ''
use_defaults = True
detect_jar = ''
detector_depth = 0

proxy_host = ''
proxy_port = ''
unsupported = False

fail_on_policies = []
polsevs = ['UNSPECIFIED', 'TRIVIAL', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER', ]

matchtypes = {
    'FILE_FILES_ADDED_DELETED_AND_MODIFIED': 'Folder',
    'FILE_DEPENDENCY': 'Dependency',
    'FILE_DEPENDENCY_DIRECT': 'Direct Dependency',
    'FILE_DEPENDENCY_TRANSITIVE': 'Transitive Dependency',
    'FILE_EXACT': 'File',
    'FILE_EXACT_FILE_MATCH': 'File',
    'FILE_SOME_FILES_MODIFIED': 'Folder',
    'MANUAL_BOM_COMPONENT': 'Manual Component',
    'MANUAL_BOM_FILE': 'Manual Component',
    'PARTIAL_FILE': 'None',
    'SNIPPET': 'Snippet',
    'BINARY': 'Binary',
    'DIRECT_DEPENDENCY_BINARY': 'Binary',
    'TRANSITIVE_DEPENDENCY_BINARY': 'Binary',
}

matchdirecttypes = [
    'FILE_FILES_ADDED_DELETED_AND_MODIFIED',
    'FILE_DEPENDENCY',
    'FILE_DEPENDENCY_DIRECT',
    'FILE_EXACT',
    'FILE_EXACT_FILE_MATCH',
    'FILE_SOME_FILES_MODIFIED',
    'MANUAL_BOM_COMPONENT',
    'MANUAL_BOM_FILE',
    'PARTIAL_FILE',
    'SNIPPET',
    'BINARY',
    'DIRECT_DEPENDENCY_BINARY',
]

default_configs = {
    'OTHER': '',
    "Cargo.lock,Cargo.toml": "",
    "Cartfile": "",
    "compile_commands.json": "",
    "Podfile.lock": "",
    "environment.yml": "",
    "conanfile.txt,conanfile.py, conan.lock": "",
    "Makefile.PL": "",
    "packrat.lock": "",
    "Gopkg.lock": "",
    "gogradle.lock": "",
    "go.mod": "",
    "vendor.json,vendor.conf": "",
    "build.gradle": "",
    "rebar.config": "",
    "package.json,package-lock.json,npm-shrinkwrap.json": "",
    "pom.xml": "",
    "pom.groovy": "",
    ".csproj,.fsproj,.vbproj,.asaproj,.dcproj,.shproj,.ccproj,.sfproj,.njsproj,.vcxproj,.vcproj,.xproj,.pyproj,.hiveproj,.pigproj,.jsproj,.usqlproj,.deployproj,.msbuildproj,.sqlproj,.dbproj,.rproj": "",
    "composer.lock,composer.json": "",
    "package.xml": "",
    "Pipfile,Pipfile.lock": "",
    "setup.py,requirements.txt": "",
    "Poetry.lock,pyproject.toml": "",
    "Gemfile.lock": "",
    "build.sbt": "",
    "Package.swift": "",
    "yarn.lock": "",
}

default_options_proj = 'DETECT_DEFAULT_OPTIONS'

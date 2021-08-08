last_scan_only = False
report_text = False
report_html = ''
junit_xml = ''
junit_type = 'pols'
# output_sarif = ''
bd_url = ''
bd_apitoken = ''
bd_trustcert = False
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

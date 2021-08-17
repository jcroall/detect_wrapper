#!/usr/bin/env python
import requests
import os

from detect_wrapper import globals


def set_global_defaults(bd):
    print(f'INFO: detect_wrapper - Creating project {globals.default_options_proj} to store default Detect options')

    try:
        projid = ''
        for i, key in enumerate(globals.default_configs.keys()):
            print(key)

            vers = {
                "versionName": key,
                "nickname": "nickname",
                # "license": {
                #     "type": "DISJUNCTIVE",
                #     "licenses": [],
                #     "license": "https://.../licenses/{licenseId}"
                # },
                "releaseComments": globals.default_configs[key],
                # "releasedOn": "2021-06-29T01:44:16.225Z",
                "phase": "DEVELOPMENT",
                "distribution": "INTERNAL",
                # "cloneFromReleaseUrl": "https://.../api/projects/{projectId}/versions/{versionId}",
                "protectedFromDeletion": False
            }
            if i == 0:
                project_data = {
                    'name': globals.default_options_proj,
                    'description': "",
                    'projectLevelAdjustments': True,
                    "versionRequest": vers,
                }
                r = bd.session.post("/api/projects", json=project_data)
                r.raise_for_status()
                projid = r.links['project']['url']
                print(f"created project {globals.default_options_proj}")
            else:
                r = bd.session.post(projid + '/versions', json=vers)
                r.raise_for_status()
                print(f"created version {key}")

    except requests.HTTPError as err:
        # more fine grained error handling here; otherwise:
        bd.http_error_handler(err)


def get_global_defaults(bd):
    configs = []

    try:
        params = {
            'q': "name:" + globals.default_options_proj,
            'sort': 'name',
        }
        projects = bd.get_resource('projects', params=params, items=False)
        if projects['totalCount'] == 0:
            return ''
        for proj in projects['items']:
            if proj['name'] != globals.default_options_proj:
                continue
            params = {
                'sort': 'versionName',
            }
            versions = bd.get_resource('versions', parent=proj, params=params, items=False)
            for i, ver in enumerate(versions['items']):
                vname = ver['versionName']
                if ':' in vname:
                    num = vname.split(':')[0]
                    vname = vname.split(':')[1]
                else:
                    num = i

                for pattern in vname.split(','):
                    configs.append(
                        {
                            'num': num,
                            'pattern': pattern,
                            'opts': ver['releaseComments']
                        }
                    )
        return sorted(configs, key=lambda i: i['num'])

    except requests.HTTPError as err:
        # more fine grained error handling here; otherwise:
        bd.http_error_handler(err)
        return configs


def get_proj(bd, projname):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    return projects


def get_projver(bd, projname, vername):
    proj = get_proj(bd, projname)
    if proj == '':
        return ''
    params = {
        'sort': 'name',
    }
    versions = bd.get_resource('versions', parent=proj, params=params)
    for ver in versions:
        if ver['versionName'] == vername:
            return ver
    return ''


def process_global_defaults(bd):
    conflist = get_global_defaults(bd)
    if globals.bd_sourcepath == '':
        sourcepath = os.getcwd()
    else:
        sourcepath = globals.bd_sourcepath

    sourcepath = os.path.expanduser(sourcepath)
    try:
        for entry in os.scandir(sourcepath):
            if entry.is_dir(follow_symlinks=False):
                continue

            # entry.name, entry.path
            ext = os.path.splitext(entry.name)[1]
            for conf in conflist:
                if conf['pattern'][0] == '.' and conf['pattern'][1:] == ext:
                    # Matched extension
                    print(f'INFO: detect_wrapper - Using default Detect options for matched file extension {ext}')
                    return conf['opts'].split(';')
                elif conf['pattern'] == entry.name:
                    # Matched complete file
                    print(f'INFO: detect_wrapper - Using default Detect options for matched file {entry.name}')
                    return conf['opts'].split(';')
    except OSError:
        print("ERROR: detect_wrapper - Unable to open folder {}\n".format(sourcepath))
        return []
    return []


def process_defaults(bd, projname, vername):
    # If no global settings then set global settings
    # If proj-ver supplied then check if proj-ver options set (custom field)
    # If no proj-ver or no proj-ver options in proj then use global settings
    # If global settings then loop through file patterns and use option for first match
    # If not file pattern match then use OTHER options
    use_defaults = True
    opts = []

    projs = get_proj(bd, globals.default_options_proj)
    if projs == '':
        set_global_defaults(bd)

    if projname != '' and vername != '':
        ver = get_projver(bd, projname, vername)
        if ver != '':
            use_defaults = False
            opts = ver['releaseComments'].split(';')

    if use_defaults:
        opts = process_global_defaults(bd)

    return opts
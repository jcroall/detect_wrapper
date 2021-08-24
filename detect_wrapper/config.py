#!/usr/bin/env python
import requests
import os

from detect_wrapper import globals


def set_global_defaults(bd):
    projs = get_proj(bd, globals.detect_default_options_proj)
    if projs != []:
        return

    print(f'INFO: detect_wrapper - Creating project {globals.detect_default_options_proj} to store default \
Detect options')
    try:
        projid = ''
        for i, key in enumerate(globals.default_configs.keys()):
            # print(key)

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
                    'name': globals.detect_default_options_proj,
                    'description': "",
                    'projectLevelAdjustments': True,
                    "versionRequest": vers,
                }
                r = bd.session.post("/api/projects", json=project_data)
                r.raise_for_status()
                projid = r.links['project']['url']
                # print(f"created project {globals.default_options_proj}")
            else:
                r = bd.session.post(projid + '/versions', json=vers)
                r.raise_for_status()
                # print(f"created version {key}")

        return

    except requests.HTTPError as err:
        # more fine grained error handling here; otherwise:
        bd.http_error_handler(err)
    return


def get_global_defaults(bd):
    configs = {}
    all_opts = []
    other_opts = []

    try:
        params = {
            'q': "name:" + globals.detect_default_options_proj,
            'sort': 'name',
        }
        projects = bd.get_resource('projects', params=params, items=False)
        if projects['totalCount'] == 0:
            return configs, all_opts, other_opts
        for proj in projects['items']:
            if proj['name'] != globals.detect_default_options_proj:
                continue
            params = {
                'sort': 'versionName',
                'limit': 100,
            }
            versions = bd.get_resource('versions', parent=proj, params=params, items=False)
            for i, ver in enumerate(versions['items']):
                vname = ver['versionName']
                if vname == 'ALL':
                    all_opts = ver['releaseComments'].split(';')
                elif vname == 'OTHER':
                    other_opts = ver['releaseComments'].split(';')
                else:
                    for pattern in vname.split(','):
                        configs[pattern] = ver['releaseComments'].split(';')
        # return sorted(configs, key=lambda i: i['num'])
        return configs, all_opts, other_opts

    except requests.HTTPError as err:
        # more fine grained error handling here; otherwise:
        bd.http_error_handler(err)
        return configs, all_opts, other_opts


def get_proj(bd, projname):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return []
    return projects


def get_projver(bd, projname, vername):
    proj = get_proj(bd, projname)
    if proj == []:
        return ''
    params = {
        'sort': 'name',
        'limit': 100,
    }
    versions = bd.get_resource('versions', parent=proj, params=params)
    for ver in versions:
        if ver['versionName'] == vername:
            return ver
    return ''


def process_global_defaults(bd):
    confdict, all_opts, other_opts = get_global_defaults(bd)
    if globals.bd_sourcepath == '':
        sourcepath = os.getcwd()
    else:
        sourcepath = globals.bd_sourcepath

    def procdir(depth, dir):
        diropts = []
        for entry in os.scandir(dir):
            if entry.is_dir(follow_symlinks=False):
                if depth < globals.detector_depth:
                    diropts += procdir(depth + 1, entry.path)
                continue

            # entry.name, entry.path
            ext = os.path.splitext(entry.name)[1]
            if entry.name in confdict.keys() and len(confdict[entry.name]) > 0:
                # Matched complete file
                print(f"INFO: detect_wrapper - Found default options '{confdict[entry.name]}' for \
matched file {entry.name}")
                diropts += confdict[entry.name]
                confdict.pop(entry.name)
            elif ext in confdict.keys() and len(confdict[entry.name]) > 0:
                # Matched extension
                print(f"INFO: detect_wrapper - Found default options '{confdict[ext]}' for \
matched file extension {ext}")
                diropts += confdict[ext].split(';')
                confdict.pop(ext)

        return diropts

    try:
        sourcepath = os.path.expanduser(sourcepath)
        opts = procdir(0, sourcepath)
        if len(opts) == 0:
            opts = other_opts
        if len(all_opts) > 0 and all_opts[0] != '' and len(opts) > 0 and opts[0] != '':
            # Remove dups
            for all_opt in all_opts:
                all_key = all_opt.split('=')[0]
                found = False
                for opt in opts:
                    if all_key == opt.split('=')[0]:
                        found = True
                if not found:
                    opts.append(all_opt)

        return opts

    except OSError:
        print("ERROR: detect_wrapper - Unable to open folder {}\n".format(sourcepath))
        return []


def process_defaults(bd, projname, vername):
    # If no global settings then set global settings
    # If proj-ver supplied then check if proj-ver options set (custom field)
    # If no proj-ver or no proj-ver options in proj then use global settings
    # If global settings then loop through file patterns and use option for first match
    # If not file pattern match then use OTHER options
    opts = ''

    if not globals.use_defaults:
        return opts


    set_global_defaults(bd)

    # if projname != '' and vername != '':
    #     ver = get_projver(bd, projname, vername)
    #     if ver != '':
    #         globals.use_defaults = False
    #         opts = ver['releaseComments']

    opts = process_global_defaults(bd)

    return opts

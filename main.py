import sys
import subprocess
import requests
import os
import datetime
from pathlib import Path

import globals
import output
import init

'''
To Do
- remove remediated vulns
- detect return code - OK
- fail on policies for latest scan only 
- sort policies by severity
'''


def get_detect_jar():
    detect_jar_download_dir = os.getenv('DETECT_JAR_DOWNLOAD_DIR')
    if detect_jar_download_dir is not None and os.path.isdir(detect_jar_download_dir):
        outfile = os.path.join(detect_jar_download_dir, "detect7.jar")
    else:
        outfile = os.path.join(str(Path.home()), "synopsys-detect", "detect7.jar")

    if os.path.isfile(outfile):
        return outfile

    url = "https://sig-repo.synopsys.com/api/storage/bds-integrations-release/com/synopsys/integration/\
synopsys-detect?properties=DETECT_LATEST_7"
    r = requests.get(url, allow_redirects=True)
    if not r.ok:
        return ''
    rjson = r.json()
    if 'properties' in rjson and 'DETECT_LATEST_7' in rjson['properties']:
        djar = rjson['properties']['DETECT_LATEST_7'][0]
        if djar != '':
            j = requests.get(djar, allow_redirects=True)
            if j.ok:
                open(outfile, 'wb').write(j.content)
                if os.path.isfile(outfile):
                    return outfile
    return ''


def run_detect(jarfile, runargs):
    args = ['java', '-jar', jarfile]
    args += runargs
    # print(runargs)
    # runargs = ['cat', 'test.output']  # DEBUG
    proc = subprocess.Popen(args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pvurl = ''
    projname = ''
    vername = ''
    while True:
        outp = proc.stdout.readline()
        if proc.poll() is not None and outp == '':
            break
        if outp:
            print(outp.strip())
            bomstr = ' --- Black Duck Project BOM:'
            projstr = ' --- Project name:'
            verstr = ' --- Project version:'
            # noinspection PyTypeChecker
            if outp.find(bomstr) > 0:
                pvurl = outp[outp.find(bomstr) + len(bomstr) + 1:].rstrip()
            if outp.find(projstr) > 0:
                projname = outp[outp.find(projstr) + len(projstr) + 1:].rstrip()
            if outp.find(verstr) > 0:
                vername = outp[outp.find(verstr) + len(verstr) + 1:].rstrip()
    retval = proc.poll()

    if projname == '' or vername == '':
        print('ERROR: No project or version identified from Detect run')
        return None, None, None

    return retval, '/'.join(pvurl.split('/')[:8]), projname, vername


def get_vulns(bd, pv):
    vulns = bd.get_json(pv + '/vulnerable-bom-components?limit=5000')
    vulnlist = []
    nvulns = []
    for vuln in vulns['items']:
        vulnname = vuln['vulnerabilityWithRemediation']['vulnerabilityName']
        vuln['sev'] = vuln['vulnerabilityWithRemediation']['overallScore']
        if vulnname not in vulnlist:
            nvulns.append(vuln)
            vulnlist.append(vulnname)

    def get_sev(c):
        return c.get('sev')

    nvulns.sort(key=get_sev, reverse=True)

    return nvulns


def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    # TODO manage ignored components
    return comps['items']


def get_pols(bd, comps):
    pols_dict = {}
    comp_pol_list = {}
    complist = []
    for comp in comps:
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if cname in complist:
            continue
        complist.append(cname)
        compurl = comp['_meta']['href']
        pollist = []
        if comp['policyStatus'] == 'IN_VIOLATION':
            comppols = bd.get_json(compurl + '/policy-rules')
            for comppol in comppols['items']:
                if comppol['name'] not in pols_dict.keys():
                    pols_dict[comppol['name']] = {
                        'name': comppol['name'],
                        'polsev': comppol['severity'],
                        'compnum': 1,
                        'comps': [cname],
                        'compurls': [comp['_meta']['href']],
                    }
                else:
                    pols_dict[comppol['name']]['compnum'] += 1
                    pols_dict[comppol['name']]['comps'].append(cname)
                    pols_dict[comppol['name']]['compurls'].append(comp['_meta']['href'])

                pollist.append(comppol['name'])
            comp_pol_list[compurl] = pollist
        else:
            comp_pol_list[compurl] = ''
    return pols_dict, comp_pol_list


def remove_vulns(vuln_comp_dict, component, vuln_list):
    if component in vuln_comp_dict.values():
        for vuln in vuln_comp_dict.keys():
            if vuln_comp_dict[vuln] == component and vuln in vuln_list:
                print("Vulnerability REMOVED: {} (due to component {} being REMOVED/IGNORED)".format(vuln, component))
                vuln_list.remove(vuln)
    return vuln_list


def add_vulns(vuln_comp_dict, component, vuln_list):
    if component in vuln_comp_dict.values():
        for vuln in vuln_comp_dict.keys():
            if vuln_comp_dict[vuln] == component and vuln in vuln_list:
                print("Vulnerability ADDED: {} (due to component {} being UNIGNORED)".format(vuln, component))
                vuln_list.append(vuln)
    return vuln_list


def proc_events(eventlist, ovulns, ocomps, opols):
    newvulns = []
    newpols = []
    newcomps = []

    for event in eventlist:

        if event['type'] == 'VULN_ADDED' and event['vuln'] not in newvulns:
            vuln = {
                'name': event['vuln'],
                'comp': event['comp'],
                'severity': event['vulnsev'],
            }
            newvulns.append(vuln)
            # print("Vulnerability ADDED: {} - Component: {}".format(event['vuln'], event['comp']))

        if event['type'] == 'POLICY_VIOLATED':
            newpols.append({
                'polstring': event['name'],
                'comp': event['comp'],
            })
            # print("Policy VIOLATED: {} - Component: {}".format(event['name'], event['comp']))

        if event['type'] == 'COMP_ADDED':
            comp = {
                'comp': event['comp'],
                'originid': event['originid'],
                'originnamespace': event['originnamespace'],
            }
            newcomps.append(comp)
            # print("Component ADDED: {}".format(event['comp']))

    vulns = []
    for ovuln in ovulns:
        for newvuln in newvulns:
            if ovuln['vulnerabilityWithRemediation']['vulnerabilityName'] == newvuln['name']:
                comp = ovuln['componentName'] + '/' + ovuln['componentVersionName']
                if comp == newvuln['comp']:
                    vulns.append(ovuln)
                    break

    comps = []
    for ocomp in ocomps:
        for newcomp in newcomps:
            if ocomp['origins'][0]['externalNamespace'] == newcomp['originnamespace'] and \
                    ocomp['origins'][0]['externalId'] == newcomp['originid']:
                comps.append(ocomp)
                break

    newpols_dict = {}
    for pol in newpols:
        polstring = pol['polstring']
        if polstring in opols.keys():
            # Policy name matches exactly
            if polstring not in newpols_dict.keys():
                newpols_dict[polstring] = opols[polstring]
                newpols_dict[polstring]['comps'] = [pol['comp']]
                newpols_dict[polstring]['compnum'] = 1
                newpols_dict[polstring]['compurls'] = []
            elif pol['comp'] not in newpols_dict[polstring]['comps']:
                newpols_dict[polstring]['comps'].append(pol['comp'])
                newpols_dict[polstring]['compnum'] += 1

        elif polstring.find(', ') >= 0:
            # Policy string may be a list of names
            for opolname in opols.keys():
                pos = polstring.find(opolname)
                if pos >= 0:
                    # Policy name exists in the string
                    # Need to check it's not a partial match
                    match = False
                    if pos == 0 and polstring[len(opolname):len(opolname)+2] == ', ':
                        # Matches first element in list
                        match = True
                    elif pos > 1 and polstring[pos-2:pos] == ', ' and \
                            (pos + len(opolname)) == len(polstring):
                        # Matches final element
                        match = True
                    elif pos > 1 and polstring[pos-2:pos] == ', ' and \
                            len(polstring) > pos+len(opolname) and polstring[pos+len(opolname)] == ',':
                        # Matches middle element
                        match = True
                    if match:
                        if opolname not in newpols_dict.keys():
                            newpols_dict[opolname] = opols[opolname]
                            newpols_dict[opolname]['comps'] = [pol['comp']]
                            newpols_dict[opolname]['compnum'] = 1
                            newpols_dict[opolname]['compurls'] = []
                        elif pol['comp'] not in newpols_dict[opolname]['comps']:
                            newpols_dict[opolname]['comps'].append(pol['comp'])
                            newpols_dict[opolname]['compnum'] += 1

    return vulns, comps, newpols_dict


def proc_journals(bd, projverurl, pjvername, starttime, vulns, comps, pols):
    # compeventaction_dict = {}
    # compeventtime_dict = {}

    if projverurl is None:
        return None, None

    headers = {'Accept': 'application/vnd.blackducksoftware.journal-4+json'}
    arr = projverurl.split('/')
    # https://poc39.blackduck.synopsys.com/api/projects/5e048290-0d1d-4637-a276-75d7cb50de6a/versions/3b14487c-c860-471d-bee1-c7d443949df5/components

    projjournalurl = "{}/api/journal/projects/{}".format('/'.join(arr[:3]), arr[5])
    verjournalurl = "{}/versions/{}?limit=50000&sort=timestamp%20desc".format(projjournalurl, arr[7])
    projjournalurl = projjournalurl + "?limit=50000&sort=timestamp%20desc"
    # response = hub.execute_get(verjournalurl, custom_headers=headers)
    #
    # if not response.ok:
    #     return None, None, None
    # jsondata = response.json()
    jsondata = bd.get_json(verjournalurl, headers=headers)

    # def addcompeevent(ceventaction_dict, ceventtime_dict, cname, ctime):
    #     if cname not in ceventaction_dict.keys():
    #         ceventaction_dict[cname] = ['ADDED']
    #         ceventtime_dict[cname] = [ctime]
    #     else:
    #         # find recent events for this component
    #         recentevents = []
    #         for index in range(len(ceventtime_dict[cname]), 0, -1):
    #

    event_list = jsondata['items']
    events = []
    for event in event_list:
        eventtime = datetime.datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if eventtime < starttime:
            break
        if event['action'] == 'Scan Mapped':
            # print(event)
            events.append({'timestamp': event['timestamp'], 'type': 'SCAN_MAPPED'})
        elif event['action'] == 'Scan Unmapped':
            # print(event)
            events.append({'timestamp': event['timestamp'], 'type': 'SCAN_UNMAPPED'})
        elif event['action'] == 'Component Added':
            if 'version' in event['currentData']:
                compname = event['objectData']['name'] + "/" + event['currentData']['version']
            else:
                compname = event['objectData']['name']
            events.append({'timestamp': event['timestamp'], 'type': 'COMP_ADDED', 'comp': compname,
                           'originid': event['currentData']['originExternalId'],
                           'originnamespace': event['currentData']['originExternalNamespace']})
            # print('RAW COMPONENT ADDED')
        elif event['action'] == 'Component Ignored':
            if 'version' in event['currentData']:
                compname = event['objectData']['name'] + "/" + event['currentData']['version']
            else:
                compname = event['objectData']['name']
            events.append({'timestamp': event['timestamp'], 'type': 'COMP_IGNORED', 'comp': compname})
            # print('RAW COMPONENT IGNORED')
        elif event['action'] == 'Component Deleted':
            if 'version' in event['currentData']:
                compname = event['objectData']['name'] + "/" + event['currentData']['version']
            else:
                compname = event['objectData']['name']
            events.append({'timestamp': event['timestamp'], 'type': 'COMP_REMOVED', 'comp': compname})
            # print('RAW COMPONENT REMOVED')
        elif event['action'] == 'Vulnerability Found':
            # print(event)
            vulnname = event['objectData']['name']
            vulnsev = event['currentData']['riskPriority']
            # vulnlink = event['objectData']['link']
            if 'releaseVersion' in event['currentData']:
                compname = event['currentData']['projectName'] + "/" + event['currentData']['releaseVersion']
            else:
                compname = event['currentData']['projectName']

            events.append(
                {
                    'timestamp': event['timestamp'],
                    'type': 'VULN_ADDED',
                    'vuln': vulnname,
                    'comp': compname,
                    'vulnsev': vulnsev,
                    'vulnorig': event['currentData']['originExternalId'],
                }
            )
            # print('RAW VULN_ADDED')
        elif event['action'] == 'Remediation Updated':
            # print(event)
            vulnname = event['objectData']['name']
            vulnsev = ''
            # vulnlink = event['objectData']['link']
            if 'componentVersion' in event['currentData']:
                compname = event['currentData']['componentName'] + "/" + event['currentData']['componentVersion']
            else:
                compname = event['currentData']['componentName']

            evtype = ''
            if event['currentData']['remediationStatus'] == 'Remediation Complete':
                evtype = 'VULN_REMEDIATED'
            if event['currentData']['remediationStatus'] == 'Ignored':
                evtype = 'VULN_IGNORED'
            if event['currentData']['remediationStatus'] == 'Patched':
                evtype = 'VULN_PATCHED'
            if evtype != '':
                # print(type)
                events.append(
                    {
                        'timestamp': event['timestamp'],
                        'type': evtype,
                        'vuln': vulnname,
                        'comp': compname,
                        'vulnsev': vulnsev,
                        'vulnorig': event['currentData']['originExternalId'],
                    }
                )
        elif event['action'] == 'Policy Violation Detected':
            if 'releaseVersion' in event['currentData']:
                compname = event['currentData']['projectName'] + "/" + event['currentData']['releaseVersion']
            else:
                compname = event['currentData']['projectName']

            events.append(
                {
                    'timestamp': event['timestamp'],
                    'type': 'POLICY_VIOLATED',
                    'name': event['currentData']['policyRuleNames'],
                    'comp': compname,
                }
            )

    # Need to check that this project has project propagation first
    #
    # headers = {'Accept': 'application/vnd.blackducksoftware.project-detail-4+json'}

    arr = projverurl.split('/')
    projurl = "{}/api/projects/{}".format('/'.join(arr[:3]), arr[5])
    # response = hub.execute_get(projurl, custom_headers=headers)
    #
    # if not response.ok:
    #     return None, None
    # projconf = response.json()
    projconf = bd.get_json(projurl)

    if 'projectLevelAdjustments' in projconf and projconf['projectLevelAdjustments']:
        # Project version uses project level adjustments

        # headers = {'Accept': 'application/vnd.blackducksoftware.journal-4+json'}
        # response = hub.execute_get(projjournalurl + '?limit=50000', custom_headers=headers)
        # if response.ok:
        #     jsondata = response.json()

        jsondata = bd.get_json(projjournalurl + '?limit=50000')

        event_list = jsondata['items']
        ver_create_date = ''
        for event in event_list:
            eventtime = datetime.datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
            if eventtime < starttime:
                break
            if event['objectData']['type'] == 'VERSION' and event['objectData']['name'] == pjvername:
                ver_create_date = event['timestamp']

            if event['timestamp'] > ver_create_date and event['objectData']['type'] == 'COMPONENT' \
                    and event['currentData']['adjustmentType'] == 'Ignore':
                if 'releaseVersion' in event['currentData']:
                    compname = event['objectData']['name'] + "/" + event['currentData']['releaseVersion']
                else:
                    compname = event['objectData']['name']
                ctype = ''
                if event['action'] == 'Adjustment Added':
                    ctype = 'COMP_IGNORED'
                elif event['action'] == 'Adjustment Deleted':
                    ctype = 'COMP_UNIGNORED'
                events.append({'timestamp': event['timestamp'], 'type': ctype, 'comp': compname})
                # print('COMP_IGNORED')
            # print(event['timestamp'] + ": ", event['currentData'])

    def my_sort(e):
        return e['timestamp']

    events.sort(key=my_sort)

    return proc_events(events, vulns, comps, pols)


def get_projver(bd, projname, vername):
    params = {
        'q': "name:" + projname,
        'sort': 'name',
    }
    projects = bd.get_resource('projects', params=params, items=False)
    if projects['totalCount'] == 0:
        return ''
    projects = bd.get_resource('projects', params=params)
    for proj in projects:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                return ver['_meta']['href']
    print("Version '{}' does not exist in project '{}'".format(projname, vername))
    return ''


def main():
    now = datetime.datetime.utcnow()
    bd, args = init.init()

    jarfile = get_detect_jar()
    if jarfile == '':
        sys.exit(1)

    rtn, pvurl, projname, vername = run_detect(jarfile, args)
    if rtn != 0:
        sys.exit(rtn)
    if pvurl == '':
        pvurl = get_projver(bd, projname, vername)
        if pvurl == '':
            sys.exit(1)

    allvulns = get_vulns(bd, pvurl)
    allcomps = get_comps(bd, pvurl)
    allpols, comp_pol_list = get_pols(bd, allcomps)
    latestvulns, latestcomps, latestpols = proc_journals(bd, pvurl, vername, now, allvulns, allcomps, allpols)

    if globals.last_scan_only:
        topcomps = output.get_top10_comps(latestvulns, latestcomps, latestpols)
        topvulns = output.get_top10_vulns(latestvulns)
        title = '(Last Scan Only)'
    else:
        topcomps = output.get_top10_comps(allvulns, allcomps, allpols)
        topvulns = output.get_top10_vulns(allvulns)
        title = ''

    if globals.last_scan_only:
        if globals.junit_xml != '':
            if globals.junit_type == 'pols' and len(latestpols) > 0:
                output.output_junit_pols(bd.base_url, globals.junit_xml, latestpols)
            elif globals.junit_type == 'comps' and len(latestcomps) > 0:
                output.output_junit_comps(bd.base_url, globals.junit_xml, latestcomps, comp_pol_list)
            elif len(latestvulns) > 0:
                output.output_junit_vulns(bd.base_url, globals.junit_xml, latestvulns)
    else:
        if globals.junit_xml != '':
            if globals.junit_type == 'pols' and len(allpols) > 0:
                output.output_junit_pols(bd.base_url, globals.junit_xml, allpols)
            elif globals.junit_type == 'comps' and len(allcomps) > 0:
                output.output_junit_comps(bd.base_url, globals.junit_xml, allcomps, comp_pol_list)
            elif len(allvulns) > 0:
                output.output_junit_vulns(bd.base_url, globals.junit_xml, allvulns)

    if globals.report_html != '':
        output.output_html_report(globals.report_html, allcomps, latestcomps, topcomps,
                                  allvulns, latestvulns, topvulns, projname, vername, pvurl, title)

    if globals.report_text:
        output.output_text_report('', allcomps, latestcomps, topcomps, allvulns, latestvulns, topvulns,
                                  projname, vername, pvurl, title)

    if len(globals.fail_on_policies) > 0 and globals.last_scan_only:
        fail = False
        for pol in latestpols.keys():
            if latestpols[pol]['polsev'] in globals.fail_on_policies:
                print('INFO: Policy violated for components added in latest scan')
                sys.exit(1)


if __name__ == '__main__':
    main()
    sys.exit(0)

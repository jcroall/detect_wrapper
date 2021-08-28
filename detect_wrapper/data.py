import datetime
from detect_wrapper import globals


def get_vulns(bd, pv):
    vulns = bd.get_json(pv + '/vulnerable-bom-components?limit=5000')
    vulnlist = []
    nvulns = []
    for vuln in vulns['items']:
        if vuln['ignored'] or vuln['vulnerabilityWithRemediation']['remediationStatus'] not in \
                ['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED']:
            continue
        vulnid = vuln['vulnerabilityWithRemediation']['vulnerabilityName']
        compname = vuln['componentName'] + '/' + vuln['componentVersionName']
        if vulnid not in vulnlist:
            vuln['comp'] = [compname]
            vuln['sev'] = vuln['vulnerabilityWithRemediation']['overallScore']
            vuln['vulnid'] = vulnid
            nvulns.append(vuln)
            vulnlist.append(vulnid)
        else:
            for nv in nvulns:
                if nv['vulnid'] == vulnid and compname not in nv['comp']:
                    nv['comp'].append(compname)
                    break

    def get_sev(c):
        return c.get('sev')

    nvulns.sort(key=get_sev, reverse=True)

    return nvulns


def get_comps(bd, pv):
    comps = bd.get_json(pv + '/components?limit=5000')
    newcomps = []
    complist = []
    for comp in comps['items']:
        if 'componentVersionName' not in comp:
            continue
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if comp['ignored'] is False and cname not in complist:
            newcomps.append(comp)
            complist.append(cname)
    return newcomps


def get_pols(bd, comps):
    pols_dict = {}
    comp_pol_list = {}
    complist = []
    pollist = []
    newcomps = []
    for comp in comps:
        cname = comp['componentName'] + '/' + comp['componentVersionName']
        if cname in complist:
            continue
        complist.append(cname)
        compurl = comp['_meta']['href']
        maxsev = -1
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
                newsev = globals.polsevs.index((comppol['severity']))
                if newsev > maxsev:
                    maxsev = newsev

                pollist.append(comppol['name'])
            comp_pol_list[compurl] = pollist
        else:
            comp_pol_list[compurl] = ''
        comp['maxpolsev'] = maxsev
        newcomps.append(comp)

    return newcomps, pols_dict, comp_pol_list


def remove_vulns(vuln_comp_dict, component, vuln_list):
    if component in vuln_comp_dict.values():
        for vuln in vuln_comp_dict.keys():
            if vuln_comp_dict[vuln] == component and vuln in vuln_list:
                # print("Vulnerability REMOVED: {} (due to component {} being REMOVED/IGNORED)".format(vuln, component))
                vuln_list.remove(vuln)
    return vuln_list


def add_vulns(vuln_comp_dict, component, vuln_list):
    if component in vuln_comp_dict.values():
        for vuln in vuln_comp_dict.keys():
            if vuln_comp_dict[vuln] == component and vuln in vuln_list:
                # print("Vulnerability ADDED: {} (due to component {} being UNIGNORED)".format(vuln, component))
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
            if 'originid' in event and 'originnamespace' in event:
                comp = {
                    'comp': event['comp'],
                    'originid': event['originid'],
                    'originnamespace': event['originnamespace'],
                }
            else:
                comp = {
                    'comp': event['comp'],
                    'originid': '',
                    'originnamespace': '',
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
        if len(ocomp['origins']) > 0 and 'externalId' in ocomp['origins'][0] and \
                'externalNamespace' in ocomp['origins'][0]:
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
            if 'originExternalId' in event['currentData']:
                events.append(
                    {
                        'timestamp': event['timestamp'],
                        'type': 'COMP_ADDED',
                        'comp': compname,
                        'originid': event['currentData']['originExternalId'],
                        'originnamespace': event['currentData']['originExternalNamespace']})
            else:
                events.append(
                    {
                        'timestamp': event['timestamp'],
                        'type': 'COMP_ADDED',
                        'comp': compname,
                        # 'originid': event['currentData']['originExternalId'],
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

            if 'originExternalId' in event['currentData']:
                vulnorig = event['currentData']['originExternalId']
            else:
                vulnorig = ''
            events.append(
                {
                    'timestamp': event['timestamp'],
                    'type': 'VULN_ADDED',
                    'vuln': vulnname,
                    'comp': compname,
                    'vulnsev': vulnsev,
                    'vulnorig': vulnorig,
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
    # projects = bd.get_resource('projects', params=params)
    for proj in projects:
        versions = bd.get_resource('versions', parent=proj, params=params)
        for ver in versions:
            if ver['versionName'] == vername:
                return ver['_meta']['href']
    print("ERROR: detect_wrapper - Version '{}' does not exist in project '{}'".format(projname, vername))
    return ''


def get_top10_comps(vulns, comps, pols):
    compsevrecs = []
    compnewrecs = []
    for comp in comps:
        direct = False
        compname = comp['componentName'] + '/' + comp['componentVersionName']
        comprec = {
            'compname': compname,
            'pols': '',
            'polsev': -1,
            'vulns': '',
            'vulnsev': -1,
            'matches': '',
            'matches_direct': '',
            'compurl': comp['componentVersion'],
        }
        matchlist = []
        matchlist_direct = []
        for orig, match in zip(comp['origins'], comp['matchTypes']):
            matchlist.append(globals.matchtypes[match] + ' (' + orig['externalNamespace'] + ')')
            if match in globals.matchdirecttypes:
                direct = True
                matchlist_direct.append(globals.matchtypes[match] + ' (' + orig['externalNamespace'] + ')')

        # comprec['compurl'] =
        pollist = []
        for polname in pols.keys():
            pol = pols[polname]
            if compname in pol['comps']:
                pollist.append('(' + pol['polsev'] + '): ' + pol['name'])
                polind = globals.polsevs.index(pol['polsev'])
                if polind > comprec['polsev']:
                    comprec['polsev'] = polind

        pollist.sort()

        if len(matchlist) > 2:
            comprec['matches'] = '{} + {} more'.format(', '.join(matchlist[:2]), len(matchlist) - 2)
        else:
            comprec['matches'] = '{}'.format(', '.join(matchlist[:2]))

        if len(matchlist_direct) > 2:
            comprec['matches_direct'] = '{} + {} more'.format(', '.join(matchlist_direct[:2]), len(matchlist_direct) -
                                                              2)
        else:
            comprec['matches_direct'] = '{}'.format(', '.join(matchlist_direct[:2]))

        if len(pollist) > 2:
            comprec['pols'] = '{} + {} more'.format(', '.join(pollist[:2]), len(pollist) - 2)
        else:
            comprec['pols'] = '{}'.format(', '.join(pollist[:2]))

        vulnlist = []
        for vuln in vulns:
            vcomp = vuln['componentName'] + '/' + vuln['componentVersionName']
            if compname == vcomp:
                vulnname = vuln['vulnerabilityWithRemediation']['vulnerabilityName'] + ' (' + \
                           vuln['vulnerabilityWithRemediation']['severity'][0] + ')'
                vulnlist.append(vulnname)
                vulnscore = vuln['vulnerabilityWithRemediation']['overallScore']
                if vulnscore > comprec['vulnsev']:
                    comprec['vulnsev'] = vulnscore
        if len(vulnlist) > 2:
            comprec['vulns'] = '{} + {} more'.format(', '.join(vulnlist[:2]), len(vulnlist) - 2)
        else:
            comprec['vulns'] = '{}'.format(', '.join(vulnlist[:2]))

        if comprec['vulnsev'] > 0 or comprec['polsev'] > 0:
            compsevrecs.append(comprec)
            if direct:
                compnewrecs.append(comprec)

    def get_sev(c):
        sev = (c.get('polsev') * 10) + c.get('vulnsev')
        return sev

    # sort by name (Ascending order)
    compsevrecs.sort(key=get_sev, reverse=True)
    return compsevrecs[:10], compnewrecs[:10]


def get_top10_vulns(vulns, url):
    urlbase = '/'.join(url.split('/')[:3]) + '/api/vulnerabilities/'
    vulnrecs = []
    vulnidlist = []
    for vuln in vulns:
        vulnid = vuln['vulnerabilityWithRemediation']['vulnerabilityName']
        vcomp = vuln['componentName'] + '/' + vuln['componentVersionName']
        vdesc = vuln['vulnerabilityWithRemediation']['description']
        vsev = vuln['vulnerabilityWithRemediation']['overallScore']
        if vulnid not in vulnidlist:
            vulnrecs.append(
                {
                    'vulnid': vulnid,
                    'sev': vsev,
                    'comps': [vcomp],
                    'desc': vdesc,
                    'vulnurl': urlbase + vulnid + '/overview',
                }
            )
            vulnidlist.append(vulnid)
        else:
            ind = vulnidlist.index(vulnid)
            vulnrecs[ind]['comps'].append(vcomp)
            if vsev > vulnrecs[ind]['sev']:
                vulnrecs[ind]['sev'] = vsev

    for vuln in vulnrecs:
        if len(vuln['comps']) > 2:
            vuln['comps'] = '{} + {} more'.format(','.join(vuln['comps'][:2]), len(vuln['comps']) - 2)
        else:
            vuln['comps'] = '{}'.format(','.join(vuln['comps'][:2]))

    def get_sev(c):
        sev = c.get('sev')
        return sev

    # sort by name (Ascending order)
    vulnrecs.sort(key=get_sev, reverse=True)
    return vulnrecs[:10]


def get_comp_counts(comps, latestcomps):
    polsevcounts = [0, 0, 0, 0, 0, 0]
    lpolsevcounts = [0, 0, 0, 0, 0, 0]
    directcount = 0
    for comp in comps:
        for match in comp['matchTypes']:
            if match in globals.matchdirecttypes:
                directcount += 1
                break
        if comp['maxpolsev'] < 0:
            continue
        polsevcounts[comp['maxpolsev']] += 1

    lcomplist = []
    ldirectcount = 0
    for comp in latestcomps:
        for match in comp['matchTypes']:
            if match in globals.matchdirecttypes:
                ldirectcount += 1
                break
        compname = comp['componentName'] + '/' + comp['componentVersionName']
        lcomplist.append(compname)
        if comp['maxpolsev'] < 0:
            continue
        lpolsevcounts[comp['maxpolsev']] += 1

    return [
        ['In Full Project', len(comps), directcount] + polsevcounts,  # DEBUG replace lcomps_violation
        ['Added in Latest Scan', len(lcomplist), ldirectcount] + lpolsevcounts,
    ]


def get_vuln_counts(vulns, latestvulns):
    vulncounts = {
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0,
    }
    for vuln in vulns:
        sev = vuln['vulnerabilityWithRemediation']['severity']
        vulncounts[sev] += 1

    lvulncounts = {
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0,
    }
    for lvuln in latestvulns:
        sev = lvuln['vulnerabilityWithRemediation']['severity']
        lvulncounts[sev] += 1

    return [
        ['In Full Project',
         vulncounts['LOW'], vulncounts['MEDIUM'], vulncounts['HIGH'], vulncounts['CRITICAL'], ],
        ['Added in Latest Scan',
         lvulncounts['LOW'], lvulncounts['MEDIUM'], lvulncounts['HIGH'], lvulncounts['CRITICAL'], ],
    ]

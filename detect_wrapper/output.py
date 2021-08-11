# import pandas as pd
# import plotly.express as px
# import plotly.io as pio
import tempfile
from dominate import document
from dominate.util import raw
from dominate.tags import *
from tabulate import tabulate

from detect_wrapper import data
from detect_wrapper import globals

# colors = px.colors.qualitative.Plotly
# seccolors = px.colors.qualitative.Light24


# def output_html(comps, vulns, pols, lcomps, lvulns, lpols):
#     fig1 = create_summary_vulnfig(vulns)
#     fig2 = create_summary_compfig(comps, lcomps)

'''
def create_summary_vulnfig(vulns, title):
    import tempfile

    df = pd.json_normalize(vulns)

    if len(df.index) > 0:
        df = df[df['ignored'] != True]
        df['vulnerabilityWithRemediation.vulnerabilityPublishedDate'] = \
            pd.DatetimeIndex(df['vulnerabilityWithRemediation.vulnerabilityPublishedDate']).strftime("%Y-%m-%d")
        df['vulnerabilityWithRemediation.vulnerabilityUpdatedDate'] = \
            pd.DatetimeIndex(df['vulnerabilityWithRemediation.vulnerabilityUpdatedDate']).strftime("%Y-%m-%d")
        df['vulnerabilityWithRemediation.remediationUpdatedAt'] = \
            pd.DatetimeIndex(df['vulnerabilityWithRemediation.remediationUpdatedAt']).strftime("%Y-%m-%d")

    fig = go.Figure()
    if len(df.index) == 0:
        return ''

    vulndf = df.drop_duplicates(subset=["vulnerabilityWithRemediation.vulnerabilityName"],
                                keep="first", inplace=False)

    vulndf = vulndf[vulndf[
        'vulnerabilityWithRemediation.remediationStatus'].isin(['NEW', 'NEEDS_REVIEW', 'REMEDIATION_REQUIRED'])
    ].sort_values(by=['vulnerabilityWithRemediation.overallScore'], ascending=False)

    df = vulndf.reset_index()

    vulns_secrisk = df.groupby(by="vulnerabilityWithRemediation.severity").componentVersion.count()
    annotations = []

    indent = 0
    colseq = [seccolors[1], seccolors[6], seccolors[7], seccolors[23], seccolors[0]]
    seq = 0
    for x in ['OK', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        if x in vulns_secrisk:
            val = vulns_secrisk[x]
            if vulns_secrisk[x] > 0:
                annotations.append(
                    dict(xref='x', yref='y',
                         x=indent + vulns_secrisk[x] / 2,
                         y=title,
                         text=x[0],
                         font=dict(family='Arial', size=12, color='rgb(0, 0, 0)'),
                         showarrow=False)
                )
                indent += vulns_secrisk[x]
        else:
            val = 0

        fig.add_trace(
            go.Bar(
                y=[title],
                x=[val],
                name=x,
                orientation='h',
                marker=dict(
                    color=colseq[seq],
                )
            )
        )
        seq += 1

    fig.update_layout(barmode='stack', showlegend=False, height=100, annotations=annotations)
    fig.update_layout(margin=dict(l=20, r=20, t=20, b=20))

    try:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as v:
            fname = v.name
        pio.write_html(fig, file=fname, auto_open=False, full_html=False)
        with open(fname) as myfile:
            htmldata = myfile.read()
        myfile.close()
    except Exception as e:
        print("ERROR: detect_wrapper - Unable to write temporary output HTML file\n" + str(e))
        return ''
    return htmldata


def create_summary_compfig(comps, lcomps):
    compdata = pd.json_normalize(comps)
    lcompdata = pd.json_normalize(lcomps)

    fig = go.Figure()
    colseq = [seccolors[1], seccolors[6], seccolors[7], seccolors[23], seccolors[0]]

    if len(compdata.index) == 0:
        return ''

    count_inviolation = len(compdata[(compdata['policyStatus'] == 'IN_VIOLATION') &
                                     (compdata['ignored'] == False)].index)
    count_notinviolation = len(compdata[(compdata['policyStatus'] == 'NOT_IN_VIOLATION') &
                                        (compdata['ignored'] == False)].index)

    count_reviewed = len(compdata[(compdata['reviewStatus'] == 'REVIEWED') &
                                  (compdata['ignored'] == False)].index)
    count_notreviewed = len(compdata[(compdata['reviewStatus'] == 'NOT_REVIEWED') &
                                     (compdata['ignored'] == False)].index)

    if len(lcompdata.index) > 0:
        lcount_inviolation = len(lcompdata[(lcompdata['policyStatus'] == 'IN_VIOLATION') &
                                           (lcompdata['ignored'] == False)].index)
        lcount_notinviolation = len(lcompdata[(lcompdata['policyStatus'] == 'NOT_IN_VIOLATION') &
                                              (lcompdata['ignored'] == False)].index)

    count_ignored = len(compdata[compdata['ignored']].index)
    count_notignored = len(compdata[compdata['ignored'] == False].index)

    annotations = []

    def calc_security(row):
        for y in row['securityRiskProfile.counts']:
            if y['countType'] == 'CRITICAL' and y['count'] > 0:
                return 'CRITICAL'
            elif y['countType'] == 'HIGH' and y['count'] > 0:
                return 'HIGH'
            elif y['countType'] == 'MEDIUM' and y['count'] > 0:
                return 'MEDIUM'
            elif y['countType'] == 'LOW' and y['count'] > 0:
                return 'LOW'
            elif y['countType'] == 'OK' and y['count'] > 0:
                return 'OK'
        return 'NONE'

    tempdf = compdata.apply(calc_security, axis=1, result_type='expand')
    compdata.insert(5, 'secrisk', tempdf)

    comp_sec = {}
    comp_sec['CRIT'] = len(compdata[(compdata['secrisk'] == 'CRITICAL') & (compdata['ignored'] == False)].index)
    comp_sec['HIGH'] = len(compdata[(compdata['secrisk'] == 'HIGH') & (compdata['ignored'] == False)].index)
    comp_sec['MED'] = len(compdata[(compdata['secrisk'] == 'MEDIUM') & (compdata['ignored'] == False)].index)
    comp_sec['LOW'] = len(compdata[(compdata['secrisk'] == 'LOW') & (compdata['ignored'] == False)].index)
    comp_sec['OK'] = len(compdata[(compdata['secrisk'] == 'OK') & (compdata['ignored'] == False)].index)

    if len(lcompdata.index) > 0:
        ltempdf = lcompdata.apply(calc_security, axis=1, result_type='expand')
        lcompdata.insert(5, 'secrisk', ltempdf)

        lcomp_sec = {}
        lcomp_sec['CRIT'] = len(lcompdata[(lcompdata['secrisk'] == 'CRITICAL') & (lcompdata['ignored'] == False)].index)
        lcomp_sec['HIGH'] = len(lcompdata[(lcompdata['secrisk'] == 'HIGH') & (lcompdata['ignored'] == False)].index)
        lcomp_sec['MED'] = len(lcompdata[(lcompdata['secrisk'] == 'MEDIUM') & (lcompdata['ignored'] == False)].index)
        lcomp_sec['LOW'] = len(lcompdata[(lcompdata['secrisk'] == 'LOW') & (lcompdata['ignored'] == False)].index)
        lcomp_sec['OK'] = len(lcompdata[(lcompdata['secrisk'] == 'OK') & (lcompdata['ignored'] == False)].index)

        colseq = [seccolors[1], seccolors[6], seccolors[7], seccolors[23], seccolors[0]]
        indent = 0
        seq = 0
        for x in ['OK', 'LOW', 'MED', 'HIGH', 'CRIT']:
            fig.add_trace(
                go.Bar(
                    y=['Latest Comps w. Vulns'],
                    x=[lcomp_sec[x]],
                    name=x,
                    orientation='h',
                    marker=dict(
                        color=colseq[seq],
                    )
                )
            )
            if x == 'OK':
                txt = 'OK'
            else:
                txt = x[0]
            if lcomp_sec[x] > 0:
                annotations.append(
                    dict(xref='x', yref='y',
                         x=indent + lcomp_sec[x] / 2,
                         y='Latest Comps w. Vulns',
                         text=txt,
                         font=dict(family='Arial', size=12,
                                   color='rgb(0, 0, 0)'),
                         showarrow=False)
                )
            seq += 1
            indent += lcomp_sec[x]

        fig.add_trace(
            go.Bar(
                y=['Latest Comp Policies'],
                x=[lcount_notinviolation],
                name='Not in Violation',
                orientation='h',
                marker=dict(
                    color=colors[2],
                )
            )
        )
        if lcount_notinviolation > 0:
            annotations.append(
                dict(xref='x', yref='y',
                     x=lcount_notinviolation / 2,
                     y='Latest Comp Policies',
                     text='No Violation',
                     font=dict(family='Arial', size=14,
                               color='rgb(255, 255, 255)'),
                     showarrow=False))
        fig.add_trace(
            go.Bar(
                y=['Latest Comp Policies'],
                x=[lcount_inviolation],
                name='In Violation',
                orientation='h',
                marker=dict(
                    color=colors[1],
                )
            )
        )
        if lcount_notinviolation > 0:
            annotations.append(
                dict(xref='x', yref='y',
                     x=lcount_notinviolation + lcount_inviolation / 2,
                     y='Latest Comp Policies',
                     text='In Violation',
                     font=dict(family='Arial', size=14,
                               color='rgb(255, 255, 255)'),
                     showarrow=False))

    indent = 0
    seq = 0
    for x in ['OK', 'LOW', 'MED', 'HIGH', 'CRIT']:
        fig.add_trace(
            go.Bar(
                y=['All Comps w. Vulns'],
                x=[comp_sec[x]],
                name=x,
                orientation='h',
                marker=dict(
                    color=colseq[seq],
                )
            )
        )
        if x == 'OK':
            txt = 'OK'
        else:
            txt = x[0]
        if comp_sec[x] > 0:
            annotations.append(
                dict(xref='x', yref='y',
                     x=indent + comp_sec[x] / 2,
                     y='All Comps w. Vulns',
                     text=txt,
                     font=dict(family='Arial', size=12,
                               color='rgb(0, 0, 0)'),
                     showarrow=False)
            )
        seq += 1
        indent += comp_sec[x]

    fig.add_trace(
        go.Bar(
            y=['Component Policies'],
            x=[count_notinviolation],
            name='Not in Violation',
            orientation='h',
            marker=dict(
                color=colors[2],
            )
        )
    )
    if count_notinviolation > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_notinviolation / 2,
                 y='Component Policies',
                 text='No Violation',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))
    fig.add_trace(
        go.Bar(
            y=['Component Policies'],
            x=[count_inviolation],
            name='In Violation',
            orientation='h',
            marker=dict(
                color=colors[1],
            )
        )
    )
    if count_notinviolation > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_notinviolation + count_inviolation / 2,
                 y='Component Policies',
                 text='In Violation',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))
    fig.add_trace(
        go.Bar(
            y=['Components Reviewed'],
            x=[count_reviewed],
            name='Reviewed',
            orientation='h',
            marker=dict(
                color=colors[5],
            )
        )
    )
    if count_reviewed > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_reviewed / 2,
                 y='Components Reviewed',
                 text='Reviewed',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))
    fig.add_trace(
        go.Bar(
            y=['Components Reviewed'],
            x=[count_notreviewed],
            name='Not Reviewed',
            orientation='h',
            marker=dict(
                color=colors[0],
            )
        )
    )
    if count_notreviewed > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_reviewed + count_notreviewed / 2,
                 y='Review Status',
                 text='Not Reviewed',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))
    fig.add_trace(
        go.Bar(
            y=['Components Ignored'],
            x=[count_notignored],
            name='Not Ignored',
            orientation='h',
            marker=dict(
                color=colors[5],
            )
        )
    )
    if count_notignored > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_notignored / 2,
                 y='Components Ignored',
                 text='Not Ignored',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))
    fig.add_trace(
        go.Bar(
            y=['Components Ignored'],
            x=[count_ignored],
            name='Ignored',
            orientation='h',
            marker=dict(
                color=colors[0],
            )
        )
    )
    if count_ignored > 0:
        annotations.append(
            dict(xref='x', yref='y',
                 x=count_notignored + count_ignored / 2,
                 y='Components Ignored',
                 text='Ignored',
                 font=dict(family='Arial', size=14,
                           color='rgb(255, 255, 255)'),
                 showarrow=False))

    fig.update_layout(barmode='stack', showlegend=False, height=300, annotations=annotations)
    fig.update_layout(margin=dict(l=20, r=20, t=20, b=20))

    try:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as v:
            fname = v.name
        pio.write_html(fig, file=fname, auto_open=False, full_html=False)

        with open(fname) as myfile:
            data = myfile.readlines()
        myfile.close()

    except Exception as e:
        print("ERROR: detect_wrapper - Unable to write temporary output HTML file\n" + str(e))
        return ''
    return data
    '''


def output_junit_vulns(bdurl, output, vulns):
    f = open(output, "w")
    f.write('''<?xml version="1.0" encoding="UTF-8"?>
    <testsuites disabled="" errors="" failures="" tests="" time="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="junit.xsd">
    <testsuite disabled="" errors="" failures="" hostname="" id="" name="Black Duck vulnerability status" package="" 
    skipped="" tests="" time="" timestamp=""
    <properties><property name="" value=""/></properties>''')

    for vuln in vulns:
        f.write("<testcase name='{} - {}'><error message='Vulnerability :".format(
            vuln['sev'],
            vuln['vulnid'],
            vuln['vulnid'],
        ))
        f.write("- Severity = " + vuln['sev'])
        f.write("- Score = {}".format(vuln['vulnerabilityWithRemediation']['overallScore']))
        f.write("- Status = " + vuln['vulnerabilityWithRemediation']['remediationStatus'])
        f.write("- Component = {}/{}".format(
            vuln['componentName'],
            vuln['componentVersionName']
        ))
        f.write("See {}/api/vulnerabilities/{}/overview".format(
            bdurl,
            vuln['vulnid'],
        ))
        f.write("'></error></testcase>")
    #
    f.write('''<system-out>system-out</system-out>
        <system-err>system-err</system-err></testsuite>
    </testsuites>''')
    f.close()

    print("Junit XML output file '{}' written with vulnerability data".format(output))


def output_junit_pols(bdurl, output, pols):
    f = open(output, "w")
    f.write('''<?xml version="1.0" encoding="UTF-8"?>
    <testsuites disabled="" errors="" failures="" tests="" time="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:noNamespaceSchemaLocation="junit.xsd">
    <testsuite disabled="" errors="" failures="" hostname="" id="" name="Black Duck policy status" package="" skipped=""
    tests="" time="" timestamp="">
    <properties><property name="" value=""/></properties>''')

    for polname in pols.keys():
        thispol = pols[polname]
        f.write("<testcase name='Policy {} ({})'><error message='Policy :{}".format(
            polname,
            thispol['polsev'],
            polname,
        ))
        f.write("- Severity = " + thispol['polsev'])
        f.write("- Num Components in Violation = {}".format(thispol['compnum']))
        f.write("- Componentlist:")
        f.write("- " + ', '.join(thispol['comps']))
        f.write("'></error></testcase>")

    f.write('''<system-out>system-out</system-out>
        <system-err>system-err</system-err></testsuite>
    </testsuites>''')
    f.close()

    print("Junit XML output file '{}' written with policy data".format(output))


def output_junit_comps(bdurl, output, comps, cp_list):
    f = open(output, "w")
    f.write('''<?xml version="1.0" encoding="UTF-8"?>
    <testsuites disabled="" errors="" failures="" tests="" time="" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:noNamespaceSchemaLocation="junit.xsd">
    <testsuite disabled="" errors="" failures="" hostname="" id="" name="Black Duck components" package="" skipped="" 
    tests="" time="" timestamp="">
    <properties><property name="" value=""/></properties>''')

    for comp in comps:
        f.write("<testcase name='{} - {}'><error message='Component: {}".format(
            comp['componentName'] + '/' + comp['componentVersionName'],
            comp['policyStatus'],
            comp['componentName'] + '/' + comp['componentVersionName'],
        ))
        if comp['policyStatus'] == 'IN_VIOLATION':
            f.write("- Policies = " + ','.join(cp_list[comp['_meta']['href']]))
        f.write("'></error></testcase>")

    f.write('''<system-out>system-out</system-out>
        <system-err>system-err</system-err></testsuite>
    </testsuites>''')
    f.close()

    print("Junit XML output file '{}' written with component data".format(output))


# def create_table(myheaders, mylist):
#     from tabulate import tabulate
#     table = [["spam",42],["eggs",451],["bacon",0]]
#     headers = ["item", "qty"]
#     return tabulate(table, headers, tablefmt="html")


def output_console_report(comps, vulns, pols, latestcomps, latestvulns, latestpols):
    comps_violation = 0
    for comp in comps:
        if comp['policyStatus'] == 'IN_VIOLATION':
            comps_violation += 1

    lcomps_violation = 0
    lcomplist = []
    lcomplist_violation = []
    for comp in latestcomps:
        lcomplist.append(comp['componentName'] + '/' + comp['componentVersionName'])
        if comp['policyStatus'] == 'IN_VIOLATION':
            lcomps_violation += 1
            lcomplist_violation.append(comp['componentName'] + '/' + comp['componentVersionName'])

    polstring = '        Total:\n'
    for pol in pols.keys():
        polstring += "        - Policy '{}' ({}): {} Violating Components\n".format(
            pol,
            pols[pol]['polsev'],
            pols[pol]['compnum'],
        )
    if len(pols) == 0:
        polstring += '        - NONE\n'

    lpolstring = '        Latest Scan Only:\n'
    for lpol in latestpols.keys():
        lpolstring += "        - Policy '{}' ({}): {} Violating Components\n".format(
            lpol,
            latestpols[lpol]['polsev'],
            latestpols[lpol]['compnum'],
        )
    if len(latestpols) == 0:
        lpolstring += '        - NONE\n'

    vulncounts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    for vuln in vulns:
        sev = vuln['vulnerabilityWithRemediation']['severity']
        vulncounts[sev] += 1

    lvulncounts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    for lvuln in latestvulns:
        sev = lvuln['vulnerabilityWithRemediation']['severity']
        lvulncounts[sev] += 1

    lastcompsstring = '    - Last Scan {}, In Violation {}'.format(
        len(latestcomps),
        lcomps_violation,
    )

    if len(latestcomps) > 0 and len(latestcomps) < len(comps):
        lastcompsstring += '''
    - Last Scan - Added components:
        - {}
    - Last Scan - Added components in violation:
        - {}'''.format(
            '\n        - '.join(lcomplist),
            '\n        - '.join(lcomplist_violation),
        )

    print('''
    SUMMARY:
    Components:
    - Total {}, In Violation {}
{}

    Policy Violations:
{}
{}
    Vulnerabilities:
    - Total:       Total {}, Crit {}, High {}, Med {}, Low {}
    - Latest Scan: Total {}, Crit {}, High {}, Med {}, Low {}    
    '''.format(
        len(comps),
        comps_violation,
        len(latestcomps),
        lcomps_violation,
        lastcompsstring,
        polstring,
        lpolstring,
        len(vulns),
        vulncounts['CRITICAL'],
        vulncounts['HIGH'],
        vulncounts['MEDIUM'],
        vulncounts['LOW'],
        len(latestvulns),
        lvulncounts['CRITICAL'],
        lvulncounts['HIGH'],
        lvulncounts['MEDIUM'],
        lvulncounts['LOW'],
    ))


def create_table(data, hdrs, fmt):
    # return tabulate(data, headers, tablefmt="simple")
    outtab = tabulate(headers=hdrs, tabular_data=data, tablefmt=fmt)
    return outtab


def output_html_report(fname,
                       comps, lcomps, topcomps, newcomps,
                       vulns, lvulns, topvulns,
                       proj, ver, pvurl, title, last_scan):
    if title == '':
        title = '(Full Project)'
    d = document(title='Black Duck OSS Report - {}/{} {}'.format(proj, ver, title))

    with d.head:
        style('''
        table, th, td{
          border: 1px solid black;
          border-collapse: collapse;
          padding: 4px;
          text-align: left;
          font-family: Arial, sans-serif;
        }
        tr:hover {background-color: #F5F5F5;}
        th {
          background-color: #4B0082;
          color: white;
        }
        h2 {
            background-color: #9370DB;
            color: white;
        }
        h1, h2, h3 {
          font-family: Arial, sans-serif;
        }''')
    d += h1(a('Project: {} - Version: {} {}'.format(proj, ver, title), href=pvurl, target='_blank'))
    d += h2('COMPONENTS')
    d += h3('Component Counts and Highest Policy Violation')
    d += raw(create_table(data.get_comp_counts(comps, lcomps),
                          ['Scope', 'Total', 'Direct'] + globals.polsevs,
                          'html').replace(
        '<table>', '''<table>
  <colgroup>
  	<col span="4">
    <col span="2" style="background-color: yellow">
    <col style="background-color: orange">
    <col style="background-color: red">
    <col style="background-color: #B22222;">
  </colgroup>'''))
    d += br()

    if len(newcomps) > 0 and last_scan:
        t = []
        for j in newcomps:
            # find compurl from allcomps
            cstring = j['compname']
            for c in comps:
                if 'componentVersionName' not in c:
                    continue
                cname = c['componentName'] + '/' + c['componentVersionName']
                if j['compname'] == cname:
                    cstring = '<a href="{}" target="_blank">{}</a>'.format(c['componentVersion'], cstring)
            t.append([cstring, j['pols'], j['vulns'], j['matches_direct']])
        d += h3('Added Components - First 10 with Direct Matches ' + title)
        d += raw(create_table(t, ['Name', 'Policies', 'Top Vulns', 'Where Found'], 'unsafehtml'))
    # else:
    #     d += h3('Added Components - Direct Matches')
    #     d += p('None')

    if len(topcomps) > 0:
        t = []
        for j in topcomps:
            t.append(['<a href="{}" target="_blank">{}</a>'.format(j['compurl'],j['compname']),
                      j['pols'], j['vulns'], j['matches']])
        d += h3('Top 10 Components with Issues ' + title)
        d += raw(create_table(t, ['Name', 'Policies', 'Top Vulns', 'Where Found'], 'unsafehtml'))
    else:
        d += h3('Top 10 Components with Issues ' + title)
        d += p('None')

    d += br()
    d += h2('VULNERABILITIES')
    d += raw(create_table(data.get_vuln_counts(vulns, lvulns),
                          ['Scope', 'LOW', 'MED', 'HIGH', 'CRIT'], 'html').replace(
        '<table>', '''<table>
  <colgroup>
  	<col>
    <col style="background-color: yellow">
    <col style="background-color: orange">
    <col style="background-color: red">
    <col style="background-color: #B22222;">
  </colgroup>'''))

    # if len(vulns) > 0:
    #     if last_scan:
    #         barname = 'Vulnerabilities ' + title
    #         d += raw(create_summary_vulnfig(lvulns, barname))
    #     else:
    #         barname = 'All Vulnerabilities'
    #         d += raw(create_summary_vulnfig(vulns, barname))

    newvulnlist = topvulns
    t = []
    for v in newvulnlist:
        t.append([
            '<a href="{}" target="_blank">{}</a>'.format(v['vulnurl'], v['vulnid'],),
            v['sev'],
            v['comps'],
            v['desc'],
        ])
    d += br()
    if len(topvulns) > 0:
        d += h3('Top 10 Vulnerabilities ' + title)
        d += raw(create_table(t, ['Vuln ID', 'Score', 'Comps', 'Description'], 'unsafehtml').replace(
        '<table>', '''<table>
  <colgroup>
  	<col style="width: 200px">
    <col>
    <col>
  </colgroup>'''))
    else:
        d += h3('Top 10 Vulnerabilities ' + title)
        d += p('None')

    f = open(fname, "w")
    f.write(d.render())
    f.close()
    print("INFO: detect_wrapper - HTML report written to file '{}'".format(fname))


def output_text_report(fname,
                       comps, lcomps, topcomps, newcomps,
                       vulns, lvulns, topvulns,
                       proj, ver, pvurl, title, last_scan):
    if title == '':
        title = '(Full Project)'

    txt = '\n==========================================================================================================\n'
    txt += 'CONSOLE REPORT\nProject: {} - Version: {} {}\n\n'.format(proj, ver, title)
    txt += 'COMPONENTS\n\n'
    txt += 'Component Counts and Highest Policy Violation\n'
    txt += create_table(data.get_comp_counts(comps, lcomps),
                          ['Scope', 'Total', 'Direct'] + globals.polsevs,
                          'fancy_grid')
    txt += '\n\n'

    if len(newcomps) > 0 and last_scan:
        t = []
        for j in newcomps:
            # find compurl from allcomps
            cstring = j['compname']
            for c in comps:
                if 'componentVersionName' not in c:
                    continue
                cname = c['componentName'] + '/' + c['componentVersionName']
                # if j['compname'] == cname:
                #     cstring = '<a href="{}" target="_blank">{}</a>'.format(c['componentVersion'], cstring)
            t.append([cstring, j['pols'], j['vulns'], j['matches_direct']])
        txt += 'Added Components - First 10 with Direct Matches ' + title + '\n'
        txt += create_table(t, ['Name', 'Policies', 'Top Vulns', 'Where Found'], 'fancy_grid')
    else:
        txt += 'Added Components - Direct Matches ' + title + '\n'
        txt += 'None'

    if len(topcomps) > 0:
        t = []
        for j in topcomps:
            t.append([j['compname'], j['pols'], j['vulns'], j['matches']])
        txt += '\n\nTop 10 Components with Issues ' + title + '\n'
        txt += create_table(t, ['Name', 'Policies', 'Top Vulns', 'Where Found'], 'fancy_grid')
    else:
        txt += '\n\nTop 10 Components with Issues ' + title + '\n'
        txt += 'None'

    txt += '\n\nVULNERABILITIES\n\n'
    txt += create_table(data.get_vuln_counts(vulns, lvulns),
                        ['Scope', 'LOW', 'MED', 'HIGH', 'CRIT'], 'fancy_grid')

    # if len(vulns) > 0:
    #     if last_scan:
    #         barname = 'Vulnerabilities ' + title
    #         d += raw(create_summary_vulnfig(lvulns, barname))
    #     else:
    #         barname = 'All Vulnerabilities'
    #         d += raw(create_summary_vulnfig(vulns, barname))

    newvulnlist = topvulns
    t = []
    for v in newvulnlist:
        t.append([
            # '<a href="{}" target="_blank">{}</a>'.format(v['vulnurl'], v['vulnid'], ),
            v['vulnid'],
            v['sev'],
            v['comps'],
            v['desc'],
        ])

    if len(topvulns) > 0:
        txt += '\n\nTop 10 Vulnerabilities ' + title + '\n'
        txt += create_table(t, ['Vuln ID', 'Score', 'Comps', 'Description'], 'fancy_grid')
    else:
        txt += '\n\nTop 10 Vulnerabilities ' + title + '\n'
        txt += 'None\n'
    txt += '\n=========================================================================================================\n'

    print(txt)


def output_text_report_old(fname,
                       comps, lcomps, topcomps,
                       newcomps, vulns, lvulns,
                       topvulns, proj, ver, pvurl, title,
                       lastscan):
    text = '\nProject: {} - Version: {}\n\n'.format(proj, ver)
    text += create_table(data.get_comp_counts(comps, lcomps), ['COMPONENTS', 'Total', 'In Violation'], 'simple')

    newcomplist = topcomps
    for j in newcomplist:
        if 'polsev' in j:
            del j['polsev']
        if 'vulnsev' in j:
            del j['vulnsev']

    t = []
    for d in newcomplist:
        t.append(list(d.values()))
    text += '\n\n' + create_table(t, ['Top 10 Comps w. Issues ' + title, 'Policies', 'Top Vulns'], 'simple')

    text += '\n\n' + create_table(data.get_vuln_counts(vulns, lvulns),
                                  ['VULNERABILITIES', 'CRIT', 'HIGH', 'MED', 'LOW'],
                                  'simple')

    newvulnlist = topvulns
    for j in newvulnlist:
        j['desc'] = j['desc'][:80]

    t = []
    for d in newvulnlist:
        t.append(list(d.values()))

    text += '\n\n' + create_table(t, ['Top 10 Vulns ' + title, 'Score', 'Comps', 'Description'], 'simple')

    if fname != '':
        f = open(fname, "w")
        f.write(text)
        f.close()
        print("INFO: detect_wrapper - Text report written to file '{}'".format(fname))
    else:
        print(text)

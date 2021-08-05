import sys
import subprocess
import requests
import os
import datetime
from pathlib import Path
import time

import globals
import output
import init
import data

'''
To Do
- remove remediated vulns - DONE
- detect return code - DONE
- fail on policies for latest scan only - DONE
- sort policies by severity
- manage ignored components - DONE
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
        print('ERROR: detect_wrapper - No project or version identified from Detect run')
        return None, None, None

    return retval, '/'.join(pvurl.split('/')[:8]), projname, vername


def main():
    print('INFO: detect_wrapper - version 1.0\n')

    now = datetime.datetime.utcnow()
    bd, args = init.init()
    ''' DEBUG
    jarfile = get_detect_jar()
    if jarfile == '':
        sys.exit(1)

    rtn, pvurl, projname, vername = run_detect(jarfile, args)
    if rtn != 0:
        sys.exit(rtn)'''

    projname = 'test-duck'
    vername = '2.0'
    pvurl = ''
    now = datetime.datetime.strptime('2021-08-04T15:59:00.000Z', '%Y-%m-%dT%H:%M:%S.%fZ')

    if pvurl == '':
        pvurl = data.get_projver(bd, projname, vername)
        if pvurl == '':
            sys.exit(1)

    # time.sleep(20)
    allvulns = data.get_vulns(bd, pvurl)
    allcomps = data.get_comps(bd, pvurl)
    allpols, comp_pol_list = data.get_pols(bd, allcomps)
    latestvulns, latestcomps, latestpols = data.proc_journals(bd, pvurl, vername, now, allvulns, allcomps, allpols)

    if globals.last_scan_only:
        topcomps, newcomps = data.get_top10_comps(latestvulns, latestcomps, latestpols)
        topvulns = data.get_top10_vulns(latestvulns)
        title = '(Last Scan Only)'
    else:
        topcomps, newcomps = data.get_top10_comps(allvulns, allcomps, allpols)
        topvulns = data.get_top10_vulns(allvulns)
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
        output.output_html_report(globals.report_html,
                                  allcomps, latestcomps, topcomps, newcomps,
                                  allvulns, latestvulns, topvulns,
                                  projname, vername, pvurl, title, globals.last_scan_only)

    if globals.report_text:
        output.output_text_report('',
                                  allcomps, latestcomps, topcomps, newcomps,
                                  allvulns, latestvulns, topvulns,
                                  projname, vername, pvurl, title, globals.last_scan_only)

    if len(globals.fail_on_policies) > 0 and globals.last_scan_only:
        for pol in latestpols.keys():
            if latestpols[pol]['polsev'] in globals.fail_on_policies:
                print('INFO: detect_wrapper - Policy violated for components added in latest scan')
                sys.exit(1)


if __name__ == '__main__':
    main()
    sys.exit(0)

#!/usr/bin/env python
import sys
import subprocess
import requests
import os
import datetime
from pathlib import Path
import time

from detect_wrapper import globals
from detect_wrapper import output
from detect_wrapper import init
from detect_wrapper import data

'''
To Do
- remove remediated vulns - DONE
- detect return code - DONE
- fail on policies for latest scan only - DONE
- sort policies by severity
- manage ignored components - DONE
'''


def get_detect_jar():
    if globals.detect_jar != '':
        return globals.detect_jar

    detect_jar_download_dir = os.getenv('DETECT_JAR_DOWNLOAD_DIR')
    if detect_jar_download_dir is not None and os.path.isdir(detect_jar_download_dir):
        outfile = os.path.join(detect_jar_download_dir, "detect7.jar")
    else:
        dir = os.path.join(str(Path.home()), "synopsys-detect")
        if not os.path.isdir(dir):
            os.mkdir(dir)
        outfile = os.path.join(dir, "detect7.jar")

    if os.path.isfile(outfile):
        return outfile

    print('INFO: detect_wrapper - Downloading detect jar file')
    url = "https://sig-repo.synopsys.com/api/storage/bds-integrations-release/com/synopsys/integration/\
synopsys-detect?properties=DETECT_LATEST_7"
    r = requests.get(url, allow_redirects=True)
    if not r.ok:
        print('ERROR: detect_wrapper - Unable to load detect config {}'.format(r.reason))
        sys.exit(1)

    rjson = r.json()
    if 'properties' in rjson and 'DETECT_LATEST_7' in rjson['properties']:
        djar = rjson['properties']['DETECT_LATEST_7'][0]
        if djar != '':
            j = requests.get(djar, allow_redirects=True)
            # if globals.proxy_host != '' and globals.proxy_port != '':
            #     j.proxies = {'https': '{}:{}'.format(globals.proxy_host, globals.proxy_port),}
            if j.ok:
                open(outfile, 'wb').write(j.content)
                if os.path.isfile(outfile):
                    return outfile
    print('ERROR: detect_wrapper - Unable to download detect jar file')
    sys.exit(1)


def run_detect(jarfile, runargs):
    print('INFO: detect_wrapper - Running Detect')

    args = ['java', '-jar', jarfile]
    args += runargs
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

    if retval != 0:
        print('ERROR: detect_wrapper - Detect returned non-zero value')
        sys.exit(2)

    if projname == '' or vername == '':
        print('ERROR: detect_wrapper - No project or version identified from Detect run')
        sys.exit(3)

    return retval, '/'.join(pvurl.split('/')[:8]), projname, vername


def main():
    print('\nINFO: Running detect_wrapper - Version 0.9beta\n')

    now = datetime.datetime.utcnow()
    bd, args = init.init()
    jarfile = get_detect_jar()

    rtn, pvurl, projname, vername = run_detect(jarfile, args)

    if not globals.wait_for_scan:
        print('INFO: detect_wrapper - Done')
        sys.exit(0)

    print('\nINFO: detect_wrapper - Processing project data ...')

    # DEBUG
    # projname = 'test-duck'
    # vername = '2.0'
    # pvurl = ''
    # now = datetime.datetime.strptime('2021-08-04T15:59:00.000Z', '%Y-%m-%dT%H:%M:%S.%fZ')

    if pvurl == '':
        pvurl = data.get_projver(bd, projname, vername)
        if pvurl == '':
            sys.exit(1)

    allvulns = data.get_vulns(bd, pvurl)
    allcomps = data.get_comps(bd, pvurl)
    allcomps, allpols, comp_pol_list = data.get_pols(bd, allcomps)
    latestvulns, latestcomps, latestpols = data.proc_journals(bd, pvurl, vername, now, allvulns, allcomps, allpols)

    if globals.last_scan_only:
        topcomps, newcomps = data.get_top10_comps(latestvulns, latestcomps, latestpols)
        topvulns = data.get_top10_vulns(latestvulns, pvurl)
        title = '(Last Scan Only)'
    else:
        topcomps, newcomps = data.get_top10_comps(allvulns, allcomps, allpols)
        topvulns = data.get_top10_vulns(allvulns, pvurl)
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

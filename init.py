import sys
import platform
import subprocess
import os
import globals

from blackduck import Client


def check_connection(url):
    import subprocess

    try:
        subprocess.check_output(['curl', '-s', '-m', '5', url], stderr=subprocess.STDOUT)
        return True
    except:
        return False


def check_platform():
    if platform.system() == "Linux" or platform.system() == "Darwin":
        return "linux"
    else:
        return "win"


def check_prereqs():
    import shutil

    # Check java
    try:
        if shutil.which("java") is None:
            return "Java JRE not installed"
        else:
            try:
                javaoutput = subprocess.check_output(['java', '-version'], stderr=subprocess.STDOUT)
                # javaoutput = 'openjdk version "13.0.1" 2019-10-15'
                # javaoutput = 'java version "1.8.0_181"'
                crit = True
                if javaoutput:
                    line0 = javaoutput.decode("utf-8").splitlines()[0]
                    prog = line0.split(" ")[0].lower()
                    if prog:
                        version_string = line0.split('"')[1]
                        if version_string:
                            major, minor, _ = version_string.split('.')
                            if prog == "openjdk":
                                crit = False
                                if major == "8" or major == "11" or major == "13" or major == "15":
                                    pass
                                else:
                                    return "Java version is not supported"
                            elif prog == "java":
                                crit = False
                                if major == "1" and (minor == "8" or minor == "11" or minor == "13" or minor == "15"):
                                    pass
                                else:
                                    return "Java version is not supported"
            except:
                crit = True

            if crit:
                return "Unable to determine Java JRE version"

    except:
        return "Unable to determine Java JRE version"

    # if pform == "linux":
    #     # check for bash and curl
    #     if shutil.which("bash") is None:
    #         return "Bash is not installed or on the PATH"

    if shutil.which("curl") is None:
        return "Curl is not installed - required"
    else:
        if not check_connection("https://detect.synopsys.com"):
            return "No connection to https://detect.synopsys.com (Proxy issue?)"
        else:
            if not check_connection("https://sig-repo.synopsys.com"):
                return "No connection to https://sig-repo.synopsys.com (Proxy issue?"

    return ""


def check_options():
    junit_type_list = ['vulns', 'pols', 'comps']

    ret = True
    args = []
    for opt in sys.argv[1:]:
        if opt == '--wrapper.detect7':
            pass
        elif opt == '--wrapper.last_scan_only':
            print('INFO: detect_wrapper - Will report on last scan data only')
            globals.last_scan_only = True
        elif opt == '--wrapper.report_text':
            print('INFO: detect_wrapper - Will output text report in console')
            globals.report_text = True
        elif opt.find('--wrapper.report_html') == 0:
            globals.report_html = opt[len('--wrapper.report_html='):]
            print('INFO: detect_wrapper - Will output HTML report to file {}'.format(globals.report_html))
        elif opt.find('--wrapper.junit_xml=') == 0:
            globals.junit_xml = opt[len('--wrapper.junit_xml='):]
            print('INFO: detect_wrapper - Will output Junit XML results to file {}'.format(globals.junit_xml))
        elif opt.find('--wrapper.junit_type=') == 0:
            globals.junit_type = opt[len('--wrapper.junit_type='):]
            if globals.junit_type not in junit_type_list:
                print("ERROR: detect_wrapper - Junit type '{}' not in supported list ()".format(globals.junit_type, ','.join(junit_type_list)))
                ret = False
            else:
                print('INFO: detect_wrapper - Will output Junit XML results for {}'.format(globals.junit_type))
        # elif opt.find('--output_sarif=') == 0:
        #     globals.output_sarif = opt[len('--output_sarif='):]
        elif opt.find('--wrapper.') == 0:
            print('WARNING: detect_wrapper - Wrapper option {} ignored'.format(opt))
        elif opt.find('--blackduck.url=') == 0:
            globals.bd_url = opt[len('--blackduck.url='):]
            args.append(opt)
        elif opt.find('--blackduck.api.token=') == 0:
            globals.bd_apitoken = opt[len('--blackduck.api.token='):]
            args.append(opt)
        elif opt == '--blackduck.trust.cert=true':
            globals.bd_trustcert = True
            args.append(opt)
        elif opt == '--detect.blackduck.scan.mode=RAPID':
            print("ERROR: detect_wrapper - RAPID scan mode not supported by detect_wrapper")
            ret = False
        elif opt.find('--detect.wait.for.results=') == 0:
            pass
        elif opt.find('--detect.policy.check.fail.on.severities=') == 0:
            sevstr = opt[len('--detect.policy.check.fail.on.severities='):]
            if sevstr != 'NONE':
                globals.fail_on_policies = sevstr.split(',')
            else:
                args.append(opt)
        else:
            args.append(opt)

    wait_for_results = True
    if len(globals.fail_on_policies) > 0:
        if not globals.last_scan_only:
            wait_for_results = False
            args.append('--detect.policy.check.fail.on.severities=' + ','.join(globals.fail_on_policies))
        else:
            args.append('--detect.wait.for.results=true')
            print('INFO: detect_wrapper - Will fail on {} policies for last scan only'.format(
                ','.join(globals.fail_on_policies)))
            # args.append('--detect.cleanup=false')

    return ret, args


def init():
    config = {}

    prereqs = check_prereqs()
    if prereqs != "":
        print("ERROR: detect_wrapper - Prerequisite not met: {}".format(prereqs))
        sys.exit(3)

    if os.getenv('BLACKDUCK_URL') is not None:
        globals.bd_url = os.getenv('BLACKDUCK_URL')
    if os.getenv('BLACKDUCK_API_TOKEN') is not None:
        globals.bd_apitoken = os.getenv('BLACKDUCK_API_TOKEN')
    if os.getenv('BLACKDUCK_TRUST_CERT') is not None:
        globals.bd_apitoken = os.getenv('BLACKDUCK_API_TOKEN')

    status, args =  check_options()
    if not status:
        sys.exit(2)

    bd = Client(
        token=globals.bd_apitoken,
        base_url=globals.bd_url,
        timeout=300,
        verify=globals.bd_trustcert  # TLS certificate verification
    )
    return bd, args
import sys
import platform
import subprocess
import os
import requests

from detect_wrapper import globals
from blackduck import Client


def check_connection(url):
    # import subprocess
    try:
        if globals.proxy_host != '' and globals.proxy_port != '':
            proxies = {
                'https': 'https://{}:{}'.format(globals.proxy_host, globals.proxy_port),
                'http': 'http://{}:{}'.format(globals.proxy_host, globals.proxy_port),
            }
            r = requests.get(url, allow_redirects=True, proxies=proxies)
        else:
            r = requests.get(url, allow_redirects=True)

        if not r.ok:
            return False
        # subprocess.check_output(['curl', '-s', '-m', '5', url], stderr=subprocess.STDOUT)
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

    # if shutil.which("curl") is None:
    #     return "Curl is not installed - required"
    # else:

    return ""


def check_options():
    junit_type_list = ['vulns', 'pols', 'comps']

    detect_opts = [
        'blackduck.url',
        'blackduck.api.token',
        'blackduck.trust.cert',
        'detect.blackduck.scan.mode',
        'detect.offline.mode',
        'detect.wait.for.results',
        'blackduck.proxy.host',
        'blackduck.proxy.port',
        'detect.policy.check.fail.on.severities',
    ]

    ret = True
    report = False
    args = []
    proxy_host = ''
    proxy_port = ''

    for detopt in detect_opts:
        envvar = detopt.upper().replace('.', '_')
        envval = os.getenv(envvar)
        if envval is not None:
            if detopt == 'blackduck.url':
                globals.bd_url = envval
            elif detopt == 'blackduck.api.token':
                globals.bd_apitoken = envval
            elif detopt == 'blackduck.trust.cert=true':
                globals.bd_trustcert = True
            elif detopt == 'detect.blackduck.scan.mode':
                if envval == 'RAPID':
                    print("ERROR: detect_wrapper - RAPID scan mode not supported")
                ret = False
            elif detopt == 'detect.offline.mode':
                print("ERROR: detect_wrapper - Offline scan not supported")
                ret = False
            elif detopt == 'blackduck.proxy.host':
                proxy_host = envval
            elif detopt == 'blackduck.proxy.port':
                proxy_port = envval
            elif detopt == '--detect.policy.check.fail.on.severities':
                sevstr = envval
                if sevstr != 'NONE':
                    globals.fail_on_policies = sevstr.split(',')

    for opt in sys.argv[1:]:
        if opt == '--wrapper.detect7':
            pass
        elif opt == '--wrapper.last_scan_only':
            print('INFO: detect_wrapper - will report on last scan only')
            globals.last_scan_only = True
        elif opt == '--wrapper.report_text':
            print('INFO: detect_wrapper - will output console report')
            globals.report_text = True
            report = True
        elif opt.find('--wrapper.report_html') == 0:
            globals.report_html = opt[len('--wrapper.report_html='):]
            print('INFO: detect_wrapper - will output report to HTML file {}'.format(globals.report_html))
            report = True
        elif opt.find('--wrapper.junit_xml=') == 0:
            globals.junit_xml = opt[len('--wrapper.junit_xml='):]
            print('INFO: detect_wrapper - will output to Junit XML file {}'.format(globals.junit_xml))
            report = True
        elif opt.find('--wrapper.junit_type=') == 0:
            globals.junit_type = opt[len('--wrapper.junit_type='):]
            if globals.junit_type not in junit_type_list:
                print("ERROR: detect_wrapper - Junit type '{}' not in supported list ()".format(
                        globals.junit_type,
                        ','.join(junit_type_list)))
                ret = False
        # elif opt.find('--output_sarif=') == 0:
        #     globals.output_sarif = opt[len('--output_sarif='):]
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
            print("ERROR: detect_wrapper - RAPID scan mode not supported")
            ret = False
        elif opt == '--detect.offline.mode=true':
            print("ERROR: detect_wrapper - Offline scan not supported")
            ret = False
        elif opt.find('--detect.wait.for.results=') == 0:
            pass
        elif opt.find('--blackduck.proxy.host=') == 0:
            proxy_host = opt[len('--blackduck.proxy.host='):]
            args.append(opt)
        elif opt.find('--blackduck.proxy.port=') == 0:
            proxy_port = opt[len('--blackduck.proxy.port='):]
            args.append(opt)
        elif opt.find('--detect.policy.check.fail.on.severities=') == 0:
            sevstr = opt[len('--detect.policy.check.fail.on.severities='):]
            if sevstr != 'NONE':
                globals.fail_on_policies = sevstr.split(',')
            else:
                args.append(opt)
        else:
            args.append(opt)

    if globals.fail_on_policies != '' and not globals.last_scan_only and not report:
        args.append('--detect.policy.check.fail.on.severities=' + ','.join(globals.fail_on_policies))
    else:
        args.append('--detect.wait.for.results=true')
        print('INFO: detect_wrapper - will wait for scan results')
        globals.wait_for_scan = True
        # args.append('--detect.cleanup=false')

    if ret is False:
        sys.exit(2)

    if proxy_host != '' and proxy_host != '':
        globals.proxy_host = proxy_host
        globals.proxy_port = proxy_port
        os.environ['HTTPS_PROXY'] = proxy_host + ':' + proxy_port
        print('INFO: detect_wrapper - setting download proxy to {}:{}'.format(proxy_host, proxy_port))
    else:
        proxy_env = ''
        if os.getenv('HTTPS_PROXY') is not None or os.getenv('HTTP_PROXY') is not None:
            if os.getenv('HTTPS_PROXY') is not None:
                proxy_env = os.getenv('HTTPS_PROXY')
            if os.getenv('HTTP_PROXY') is not None:
                proxy_env = os.getenv('HTTP_PROXY')
            globals.proxy_host = ':'.join(proxy_env.split(':')[:2])
            globals.proxy_port = proxy_env.split(':')[2]
            args.append('--blackduck.proxy.host=' + globals.proxy_host)
            args.append('--blackduck.proxy.port=' + globals.proxy_port)
            print('INFO: detect_wrapper - setting Detect proxy to {}:{}'.format(globals.proxy_host, globals.proxy_port))

    return args


def init():
    prereqs = check_prereqs()
    if prereqs != "":
        print("Prerequisite not met: {}".format(prereqs))
        sys.exit(3)

    if os.getenv('BLACKDUCK_URL') is not None:
        globals.bd_url = os.getenv('BLACKDUCK_URL')
    if os.getenv('BLACKDUCK_API_TOKEN') is not None:
        globals.bd_apitoken = os.getenv('BLACKDUCK_API_TOKEN')
    if os.getenv('BLACKDUCK_TRUST_CERT') is not None:
        globals.bd_apitoken = os.getenv('BLACKDUCK_API_TOKEN')

    args = check_options()

    if not check_connection("https://detect.synopsys.com"):
        print('ERROR: detect_wrapper - No connection to https://detect.synopsys.com (Proxy issue?)')
        sys.exit(2)
    if not check_connection("https://sig-repo.synopsys.com"):
        print('ERROR: detect_wrapper - No connection to https://sig-repo.synopsys.com (Proxy issue?)')
        sys.exit(2)

    if globals.bd_url == '' or globals.bd_apitoken == '':
        print('ERROR: detect_wrapper - No Black Duck server credentials supplied (--blackduck.url and \
--blackduck.api.token)')
        sys.exit(2)
    if not check_connection(globals.bd_url):
        print("ERROR: detect_wrapper - No connection to {} (Invalid URL or Proxy issue?)".format(globals.bd_url))
        sys.exit(2)

    bd = Client(
        token=globals.bd_apitoken,
        base_url=globals.bd_url,
        timeout=300,
        verify=globals.bd_trustcert  # TLS certificate verification
    )
    return bd, args

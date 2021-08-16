import sys
import platform
import subprocess
import os
import requests

from detect_wrapper import globals
from blackduck import Client

check_detect_opts = [
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


def check_connection(url):
    # import subprocess
    try:
        # if globals.proxy_host != '' and globals.proxy_port != '':
        #     prox = {
        #         'http': '{}:{}'.format(globals.proxy_host, globals.proxy_port),
        #     }
        #     r = requests.get(url, allow_redirects=True, proxies=prox)
        # else:
        r = requests.get(url, allow_redirects=True, proxies={})

        if not r.ok:
            return False
        # subprocess.check_output(['curl', '-s', '-m', '5', url], stderr=subprocess.STDOUT)
        return True
    except Exception as exc:
        print(str(exc))
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

        if crit:
            return "Unable to determine Java JRE version"

    except Exception as exc:
        return "Unable to determine Java JRE version"

    # if pform == "linux":
    #     # check for bash and curl
    #     if shutil.which("bash") is None:
    #         return "Bash is not installed or on the PATH"

    # if shutil.which("curl") is None:
    #     return "Curl is not installed - required"
    # else:

    return ""


def process_opt(opt, val):
    use_opt = True
    if opt.find('--') == 0:
        opt = opt[2:]

    if opt == 'blackduck.url':
        globals.bd_url = val
    elif opt == 'blackduck.api.token':
        globals.bd_apitoken = val
    elif opt == 'blackduck.trust.cert':
        if val == 'true':
            globals.bd_trustcert = True
    elif opt == 'detect.blackduck.scan.mode':
        if val == 'RAPID':
            print("ERROR: detect_wrapper - RAPID scan mode not supported")
        globals.unsupported = True
    elif opt == 'detect.offline.mode':
        print("ERROR: detect_wrapper - Offline scan not supported")
        globals.unsupported = True
    elif opt == 'blackduck.proxy.host':
        globals.proxy_host = val
    elif opt == 'blackduck.proxy.port':
        globals.proxy_port = val
    elif opt == 'detect.policy.check.fail.on.severities':
        if val != 'NONE':
            globals.fail_on_policies = val.split(',')
    elif opt == 'detect.wait.for.results':
        use_opt = False
    return use_opt


def check_envvars():
    for detopt in check_detect_opts:
        envvar = detopt.upper().replace('.', '_')
        envval = os.getenv(envvar)
        if envval is not None:
            process_opt(detopt, envval)
    return


def check_spring_config():
    # Check for spring config file
    optfile = ''
    for opt in sys.argv[1:]:
        if opt.find('--spring.profiles.active=') == 0:
            optfile = 'application-{}.yml'.format(opt[len('--spring.profiles.active='):])
            if not os.path.isfile(optfile):
                print(os.getcwd())
                optfile = ''
            break

    if optfile == '':
        return

    file1 = open(optfile, "r")
    for line in file1:
        if len(line.strip()) == 0 or line.strip().find('#') == 0:
            # Comment line
            continue
        arr = line.strip().split(': ')
        if len(arr) != 2:
            continue
        key = arr[0]
        val = arr[1]
        if key in check_detect_opts:
            process_opt(key, val)
    return


def check_all_options():
    junit_type_list = ['vulns', 'pols', 'comps']

    report = False
    args = []

    check_spring_config()
    check_envvars()

    for opt in sys.argv[1:]:
        arr = opt.split('=')
        key = ''
        val = ''
        if len(arr) >= 1:
            key = arr[0]
        if len(arr) >= 2:
            val = '='.join(arr[1:])

        if key == '--wrapper.detect7':
            pass
        elif key == '--wrapper.last_scan_only':
            print('INFO: detect_wrapper - Will report on last scan only')
            globals.last_scan_only = True
        elif key == '--wrapper.report_text':
            print('INFO: detect_wrapper - Will output console report')
            globals.report_text = True
            report = True
        elif key == '--wrapper.report_html':
            globals.report_html = val
            print('INFO: detect_wrapper - Will output report to HTML file {}'.format(globals.report_html))
            report = True
        elif key == '--wrapper.junit_xml':
            globals.junit_xml = val
            print('INFO: detect_wrapper - Will output to Junit XML file {}'.format(globals.junit_xml))
            report = True
        elif key == '--wrapper.junit_type':
            globals.junit_type = val
            if globals.junit_type not in junit_type_list:
                print("ERROR: detect_wrapper - Junit type '{}' not in supported list ()".format(
                        globals.junit_type,
                        ','.join(junit_type_list)))
                globals.unsupported = True
        elif key == '--wrapper.detect_jar':
            if os.path.isfile(val):
                globals.detect_jar = val
                print('INFO: detect_wrapper - Will use existing Detect jar (no download) {}'.format(globals.detect_jar))
            else:
                print('ERROR: detect_wrapper - Supplied detect jar {} does not exist'.format(val))
                globals.unsupported = True
        # elif opt.find('--output_sarif=') == 0:
        #     globals.output_sarif = opt[len('--output_sarif='):]
        elif process_opt(key, val):
            args.append(opt)

    if globals.fail_on_policies != '' and not globals.last_scan_only and not report:
        args.append('--detect.policy.check.fail.on.severities=' + ','.join(globals.fail_on_policies))
    elif globals.junit_xml != '' or globals.report_html != '' or globals.report_text:
        args.append('--detect.wait.for.results=true')
        print('INFO: detect_wrapper - Will wait for scan results')
        globals.wait_for_scan = True
        # args.append('--detect.cleanup=false')
    else:
        print('INFO: detect_wrapper - Nothing to do after Detect so will not wait')

    if globals.unsupported:
        sys.exit(2)

    if globals.proxy_host != '' and globals.proxy_port != '':
        os.environ['HTTP_PROXY'] = 'http://' + globals.proxy_host + ':' + globals.proxy_port
        print('INFO: detect_wrapper - setting download proxy to https://{}:{}'.format(globals.proxy_host, globals.proxy_port))
    else:
        proxy_env = ''
        if os.getenv('HTTPS_PROXY') is not None or os.getenv('HTTP_PROXY') is not None:
            if os.getenv('HTTP_PROXY') is not None:
                proxy_env = os.getenv('HTTP_PROXY')
            if os.getenv('HTTPS_PROXY') is not None:
                proxy_env = os.getenv('HTTPS_PROXY')

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

    args = check_all_options()

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

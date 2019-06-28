#!/usr/bin/env python3

# TODO either 443 or 80?
# todo stop webenum when false positives, restart without that status code

import os
import io
import sys
import socket
import subprocess

from argparse import ArgumentParser
from multiprocessing.dummy import Pool as ThreadPool  # single thread async
from threading import Thread                          # single thread async

from libnmap.parser import NmapParser

NMAP_TCP_PORTS = "nmap -p- --max-retries 2 -Pn {0} | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//"
NMAP_TCP_SCAN = 'nmap -Pn -sC -sV -script-args=unsafe=1 -p {0} -oX {1} -oN {2} {3}'
NMAP_UDP_QUICK = 'nmap -sU -Pn -p 161 -oX {0} -oN {1} {2}'
NMAP_UDP_FULL = 'nmap -sU -Pn --max-retries 2 -oX {0} -oN {1} {2}'
# MASSCAN_UDP = 'masscan -p1,U:1-65535 {0} --rate=800 > {1} 2>{2}'
NIKTO = 'nikto -host {0}:{1} -Format html -o {2}'
DIRSEARCH = 'dirsearch -w {0} -u {1}:{2} -e {3} --plain-text-report {4}'
GOBUSTER = 'gobuster -q -r -e -k -w {0} -u {1}:{2} -x {3} -o {4}'
SMB_CMD = 'nmap -Pn -p445 --script vuln --script smb-enum* -oN {0} {1}'

# todo move the rest of the commands up here
# todo make the commands configurable on user (command line) input...

conf_handler = None


class ConfigurationHandler(object):

    def __init__(self, args):
        parser = ArgumentParser()

        parser.add_argument(
            "-t",
            dest="targets",
            nargs='+',
            type=str,
            required=True,
            help="Set a list of targets to target")
        parser.add_argument(
            "-o",
            dest="output_directory",
            required=False,
            help="Set the root directory for the results",
            default=os.curdir)
        parser.add_argument(
            "-w",
            dest="web_wordlist",
            required=False,
            help="Set the wordlist for webserver directory scan",
            default='/root/wordlists/web/paths.txt')
        parser.add_argument(
            "--skip-nmap",
            dest="skip_nmap",
            required=False,
            help="Skip nmap/masscan ~ Parse the info produced by earlier run",
            action="store_true"
        )

        arguments = parser.parse_args(args)
        self.targets = arguments.targets
        self.rootdir = os.path.abspath(arguments.output_directory)
        self.web_wordlist = arguments.web_wordlist
        self.skip_nmap = arguments.skip_nmap

    def init(self):
        ctxs = []

        for tgt in self.targets:
            tgt = tgt.strip(',;/-\\')
            host = socket.gethostbyaddr(tgt)[0]
            
            tgt_path = os.path.join(self.rootdir, host, 'scan')
            if not os.path.exists(tgt_path):
                print("creating ", tgt_path)
                os.makedirs(tgt_path)
            ctxs.append({
                'target': tgt.rstrip('/'),
                'tgtdir': tgt_path
            })

        return ctxs


def _exec(cmd, stdout=None, stderr=None, append=False):
    """
    :type append: bool
    :type stderr: int or str
    :type stdout: int or str
    :rtype: int
    """
    mode = 'ab' if append else 'wb'

    if stdout and isinstance(stdout, str) and len(stdout) > 0:
        stdout_fd = open(stdout, mode)
    else:
        stdout_fd = stdout
    if stderr and isinstance(stderr, str) and len(stderr) > 0:
        stderr_fd = open(stderr, mode)
    else:
        stderr_fd = stderr

    print("*** Running: ***\n$ %s" % cmd)
    sys.stdout.flush()
    exit_code = subprocess.run(cmd.split(), stdout=stdout_fd, stderr=stderr_fd, check=True)
    # print("***** EOP: {0} ~~~ with EXIT CODE: {1} ~~~".format(cmd, exit_code.returncode))
    # sys.stdout.flush()

    if isinstance(stdout_fd, io.IOBase):
        stdout_fd.close()
    if isinstance(stderr_fd, io.IOBase):
        stderr_fd.close()
    return exit_code


def _filter(services):
    """
    :type services: list
    :rtype list
    """
    # print(services)
    return services  # todo


def snmp_enum(ctx, service):
    target = ctx['target']
    tgtdir = ctx['tgtdir']

    port = service.port
    if port != 161:
        print("WARNING: target {} was identified running SNMP on port {1}".format(
            target, port))
        # TODO what to DO here?? CLIs don't support port option

    error_log = os.path.join(tgtdir, 'snmp.error')

    # 1) 161
    try:
        outfile = os.path.join(tgtdir, 'snmp_161.txt')
        cmd = 'onesixtyone {0}'.format(target)
        _exec(cmd, stdout=outfile, stderr=error_log)
    except Exception as e:
        print(e)
        # just go on, consecutive tasks of a single thread

    # 2) snmp-check
    try:
        outfile = os.path.join(tgtdir, 'snmp_check.txt')
        cmd = 'snmp-check {0}'.format(target)
        _exec(cmd, stdout=outfile, stderr=error_log)
    except Exception as e:
        print(e)
        # just go on, consecutive tasks of a single thread

    # 3) snmp-walk
    try:
        outfile = os.path.join(tgtdir, 'snmp_walk.txt')
        cmd = 'snmpwalk {0}'.format(target)
        _exec(cmd, stdout=outfile, stderr=error_log)
        cmd = 'snmpwalk -v2c -c public {0}'.format(target)
        _exec(cmd, stdout=outfile, stderr=error_log, append=True)
    except Exception as e:
        print(e)
        # just go on, consecutive tasks of a single thread


def smb_enum(ctx, service):
    target = ctx['target']
    tgtdir = ctx['tgtdir']

    if service.port not in (137, 139, 445):
        print("WARNING: SMB/netbions detected on port {}?".format(
            service.port))

    # 1) Scan with nmap scripts ~ This SHOULD have been ALREADY done at the initial scan
    try:
        # xml_path = os.path.join(tgtdir, 'smb.xml')
        txt_path = os.path.join(tgtdir, 'smb.nmap')
        cmd = SMB_CMD.format(txt_path, target)
        _exec(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # the scripts invoked already by nmap by default should be:
        # locate -r '\.nse$'|xargs grep categories|grep 'default\|version'|grep smb
    except Exception as e:
        print(e)

    outfile = os.path.join(tgtdir, 'smb.txt')

    # 2)
    smbmap_cmd = 'smbmap -H {0}'.format(target)
    try:
        _exec(smbmap_cmd, stdout=outfile, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(e)

    # 3)
    enum4linux_cmd = 'enum4linux {0}'.format(target)
    try:
        _exec(enum4linux_cmd, stdout=outfile, stderr=subprocess.DEVNULL, append=True)
    except Exception as e:
        print(e)

    # 4)
    # nbtscan

    # 5)
    # outfile = os.path.join(tgtdir, 'smb_mitm.txt')
    # impacket_cmd = 'smbrelayx.py -h {0}'.format(target)
    # _exec(impacket_cmd, stdout=outfile, stderr=error_log)


def web_enum(ctx, service):
    target = ctx['target']
    tgtdir = ctx['tgtdir']
    port = service.port
    prot = 'https' if 'https' in service.service.lower() else 'http'
    target = "{0}://{1}".format(prot, target)
    webserver = service.service_dict.get('product')

    ext = 'php,html'
    if webserver and len(webserver) > 2:
        if 'IIS' in webserver.upper():
            ext += ',aspx'
        elif 'APACHE' in webserver.upper():
            pass
        elif 'NGINX' in webserver.upper():
            pass
        else:
            ext += ',txt'
    # todo heuristic on `ext` needs improvement
    # error_log = os.path.join(ctx['tgtdir'],  'port-{}.error'.format(port))

    outfile = os.path.join(tgtdir, 'port-{}-nikto.html'.format(port))
    cmd = NIKTO.format(target, port, outfile)
    cmd += ' --ssl' if port == 443 or prot == 'https' else ''
    _exec(cmd, stdout=subprocess.DEVNULL)

    outfile = os.path.join(tgtdir, 'port-{}-gobuster.txt'.format(port))
    cmd = GOBUSTER.format(conf_handler.web_wordlist, target, port, ext, outfile)
    _exec(cmd, stdout=subprocess.DEVNULL)

    # os.system("cat {0} | sort -u | uniq > {1}".format(tmp_out, outfile))
    # os.system("rm %s" % tmp_out)


def udp_scan_quick(target, tgtdir):
    """
    Currently we care only for snmp at this stage
    :param target: hostname or IP
    :param tgtdir: root scan directory for that target
    :rtype: list
    """
    xml_path = os.path.join(tgtdir, 'udp.xml')
    txt_path = os.path.join(tgtdir, 'udp.nmap')

    if not conf_handler.skip_nmap:
        cmd = NMAP_UDP_QUICK.format(xml_path, txt_path, target)
        _exec(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    report = NmapParser.parse_fromfile(xml_path)
    if not report.hosts:
        return None
    
    host = report.hosts[0]  # each thread scans a single host
    return host.services


def udp_scan_full(target, tgtdir):
    """
    Scans top 1000 udp ports

    :type target: str
    :param target: hostname or IP
    :type tgtdir: str
    :param tgtdir: root scan directory for that target
    :return: None
    """
    xml_path = os.path.join(tgtdir, 'udp.xml')
    txt_path = os.path.join(tgtdir, 'udp.nmap')

    # masscan instead and then pass to nmap the ports?
    cmd = NMAP_UDP_FULL.format(xml_path, txt_path, target)
    _exec(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tcp_scan(target, tgtdir):
    """
    Each thread scans a single target

    :type target: str
    :param target: hostname or IP
    :type tgtdir: str
    :param tgtdir: root scan directory for that target
    :rtype: list
    """
    xml_path = os.path.join(tgtdir, 'tcp.xml')
    txt_path = os.path.join(tgtdir, 'tcp.nmap')

    if not conf_handler.skip_nmap:
        cmd = NMAP_TCP_PORTS.format(target)
        ports = os.popen(cmd).read()
        print("##### Host {0} has open ports: {1} #####".format(target, ports))
        cmd = NMAP_TCP_SCAN.format(ports, xml_path, txt_path, target)
        _exec(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    report = NmapParser.parse_fromfile(xml_path)
    host = report.hosts[0]

    return host.services


def dispatch(ctx):
    target = ctx['target']
    tgtdir = ctx['tgtdir']
    print("Scanning %s" % target)

    tcp_services = tcp_scan(target, tgtdir)
    udp_services = udp_scan_quick(target, tgtdir)
    services = tcp_services + udp_services
    services = _filter(services)

    smb_done = False
    threads = []
    for service in services:
        if service.state.upper() == 'OPEN':
            s = service.service.upper()
            if 'HTTP' in s or 'HTTPS' in s:
                t = Thread(target=web_enum, args=(ctx, service))
            elif ('SMB' in s or 'NETBIOS' in s or 'MICROSOFT-DS' in s) and not smb_done:
                t = Thread(target=smb_enum, args=(ctx, service))
                smb_done = True   # multiple ports, do not rescan
            elif 'SNMP' in s:
                t = Thread(target=snmp_enum, args=(ctx, service))
            else:
                continue
            threads.append(t)
            t.start()

    t = Thread(target=udp_scan_full, args=(target, tgtdir))
    threads.append(t)
    t.start()

    for t in threads:
        t.join()
    print(">> End of scan for ** %s **" % target)


def main():
    global conf_handler

    conf_handler = ConfigurationHandler(sys.argv[1:])
    ctxs = conf_handler.init()

    num_init_threads = min(len(conf_handler.targets), 10)
    with ThreadPool(num_init_threads) as p:
        p.map(dispatch, ctxs)

    print("Finished enumeration process")


if __name__ == "__main__":
    main()

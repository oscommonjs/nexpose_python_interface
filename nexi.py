#!/usr/bin/python

import argparse
import os
from nexpose import Nexpose

user_vars = {
    "nexpose_user": "username",
    "nexpose_passwd": "password",
    "nexpose_ip": "127.0.0.1",
    "nexpose_port": "3780"
}

def create_instance():
    nex = Nexpose(user_vars)
    return nex

def check_options(args):
    nex = create_instance()
    if(args.nx_list):
        opt_list(nex)
    if(args.nx_create):
        opt_create(nex,args)
    if(args.nx_scan):
        opt_scan(nex,args)
    if(args.nx_check):
        opt_check(nex, args)
    if(args.nx_report):
        opt_report(nex,args)
    if(args.nx_vuln_list):
        opt_vuln_list(nex)
    if(args.nx_scan_activity):
        opt_scan_activity(nex)
    if(args.nx_delete):
        opt_delete(nex,args)

def opt_list(nex):
    nex.list_site()

def opt_create(nex, args):
    nx_site_name = args.nexpose_site_name
    templateID = args.templateID
    hosts_string = str(args.hosts_string)
    nex.create_site(nx_site_name, hosts_string, templateID)

def opt_scan(nex, args):
    siteID = args.siteID
    nex.scan_site(siteID)

def opt_check(nex, args):
    scanID = args.scanID
    nex.check_scan(scanID)

def opt_report(nex, args):
    report_name = args.report_name
    scanID = args.scanID
    file_type = args.file_type
    if(report_name != None):
        if(scanID != None):
            data = nex.generate_report(file_type, scanID)
            print "[+] Saving the report."

            # Prepare to write file
            if(report_name != None):
                report_name = datetime.datetime.now().strftime("%Y-%m-%d_%H%M_") + report_name
                try:
                    f = open(report_name, 'w')
                    f.write(data)
                except:
                    print "[-] Could not write the file."
                    exit(-1)
            else:
                print "[-] No reort name given."
        else:
            print "[-] A scan_id is required to generate report"
    else:
        print "[-] A filename is required to generate report"

def opt_vuln_list(nex, args):
    nex.vuln_list()

def opt_scan_activity(nex):
    nex.scan_activity()

def opt_delete(nex, args):
    siteID = args.siteID
    nex.delete_site(siteID)

def main():
    parser = argparse.ArgumentParser(description='Interact with Nexpose API.')
    parser.add_argument('-c', action='store_true', dest='nx_create', help='create Nexpose site', default=False)
    parser.add_argument('-C', action='store_true', dest='nx_check', help='check the status of a site scan', default=False)
    parser.add_argument('-d', action='store_true', dest='nx_delete', help='delete Nexpose site', default=False)
    parser.add_argument('-f', action='store', dest='report_name', help='filename to write report, default output.pdf', default='output')
    parser.add_argument('-H', action='store', dest='hosts_string', help='specify host(s) to add to a site, can use a /24 CIDR only')
    parser.add_argument('-i', action='store', dest='nexpose_ip', help='ip to connect to nexpose API', default=None)
    parser.add_argument('-I', action='store', dest='scanID', help='specify scan-id')
    parser.add_argument('-l', action='store_true', dest='nx_list', help='list nexpose sites', default=False)
    parser.add_argument('-n', action='store', dest='nexpose_site_name', help='specify the name of the site to be created')
    parser.add_argument('-p', action='store', dest='nexpose_port', help='nexpose API port number')
    parser.add_argument('-r', action='store_true', dest='nx_report', help='create adhoc scan report', default=False)
    parser.add_argument('-s', action='store_true', dest='nx_scan', help='scan a nexpose site', default=False)
    parser.add_argument('-S', action='store', dest='siteID', help='nexpose site-id')
    parser.add_argument('-t', action='store', dest='templateID', help='define scan template to use, default full-audit.', default='full-audit')
    parser.add_argument('-v', action='store_true', dest='nx_vuln_list', help='view the vulnerability listing', default=False)
    parser.add_argument('--report-type', action='store', dest='file_type', help="""choose file type
                        (pdf|html|rtf|xml|text|rawxml|raw-xml-v2|ns-xml|qualys-xml), default pdf""",
                        default='pdf')
    parser.add_argument('--scan-activity', action='store_true', dest='nx_scan_activity', help='check nexpose scan activity', default=False)

    args = parser.parse_args()
    if(args.nexpose_ip != None):
        user_vars['nexpose_ip'] = args.nexpose_ip
    if(args.nexpose_port != None):
        user_vars['nexpose_port'] = args.nexpose_port
    check_options(args)

if __name__ == "__main__":
    main()

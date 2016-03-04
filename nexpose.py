import os
import httplib
import time, datetime
import xmltodict, json
from xml.dom.minidom import parseString
import base64

# Fix bug with self signed SSL certs
import ssl
#ssl._create_default_https_context = ssl._create_unverified_context

# Set debug info
DEBUG = False

class Nexpose():


    def __init__(self, user_vars):
        """Initializing variables."""
        # User defined variables
        self.nexpose_user = user_vars['nexpose_user']
        self.nexpose_passwd = user_vars['nexpose_passwd']
        self.nexpose_ip = user_vars['nexpose_ip']
        self.nexpose_port = user_vars['nexpose_port']
        # Nexpose defined variables
        self.session_id = ""
        self.site_id = ""
        self.scan_id = ""

    def nx_connection(self):
        con = httplib.HTTPSConnection(self.nexpose_ip, self.nexpose_port)
        return con

    def nx_login(self):
        """Connect to Nexpose and obtain session-id."""
        con = self.nx_connection()
        xml_request = """<LoginRequest sync-id="5"
                        user-id="%s" password="%s" />""" % (self.nexpose_user, self.nexpose_passwd)
        response = self.nx_request(con, xml_request, "[-] Error making login call")
        data = response.read()
        # Parse data
        success_value = self.parse_data(data, 'LoginResponse', "[-] Login response error occured.", True)
        # Check login success
        if(success_value == 0 or self.session_id == None):
            print "[-] Login Error\n";
            exit(-1)

    def nx_request(self, con, xml_request, error_msg, headers={"Content-type": "text/xml"}):
        """Make request to Nexpose API."""
        try:
            con.request("POST", "/api/1.1/xml", xml_request, headers)
        except:
            print error_msg
            exit(-1)
        return con.getresponse()

    def nx_response(self, response):
        """Print the response and data received, then return data."""
        data = response.read()
        output = xmltodict.parse(data, xml_attribs='xml_attribs')
        print json.dumps(output, indent=2)
        return data

    def parse_data(self, data, tag, error_msg, sessionID=False):
        """Parse xml data returned from xml request for needed variables."""
        dom = parseString(data)
        try:
            xmlTag = dom.getElementsByTagName(tag)[0]
            success_value = xmlTag.getAttribute("success")
            if(DEBUG):
                print "success_value: %s" % success_value
            if(sessionID):
                self.session_id = xmlTag.getAttribute("session-id");
            else:
                if(self.site_id == ""):
                    self.site_id = xmlTag.getAttribute("site-id");
            if(DEBUG):
                print "session_id: %s" % self.session_id
                print "site_id: %s" % self.site_id
        except:
            print error_msg
            exit(-1)
        return success_value

    def check_session(self):
        if(self.session_id == ""):
            self.nx_login()

    def check_value(self, success_value, msg):
        if(success_value == 0):
            print msg
            exit(-1)

    def check_siteID(self, siteID):
        if(siteID != None):
            self.site_id = siteID

    def create_site(self,nexpose_site_name, hosts_string, template_id):
        """Create a Nexpose site and add assets to the site."""
        # Check if session_id is empty, get session if empty.
        self.check_session()

        # Set site name
        nexpose_site_name = nexpose_site_name

    print hosts_string
        # Split hosts in hosts_string
        if("," in hosts_string):
        print "inside split if statement"
            hosts_string = hosts_string.split(",")
            hosts = []
            for host in hosts_string:
                host_tag = "<host>%s</host>" % host
                hosts.append(host_tag)
            hosts_string = hosts

        # Check for /24 in host strings.
        if("/24" in hosts_string):
            print "inside /24 if statement"
            hosts = []
            for i in range(1, 255):
                ip = hosts_string[:hosts_string.find("/")-1] + str(i)
                host_tag = "<host>%s</host>" % ip
                hosts.append(host_tag)
            hosts_string = hosts
        if(type(hosts_string) is not list):
        print "inside else statement"
            hosts_string = "<host>" + hosts_string + "</host>"

        # Build site creation request.
        xml_request = """<SiteSaveRequest session-id="%s"> """ % self.session_id
        xml_request += """<Site id="-1" name="%s" description="Quick Scan"> """ % nexpose_site_name
        xml_request += """<Hosts>""" + str(hosts_string) + """</Hosts> <Credentials></Credentials> """
        xml_request += """<Alerting></Alerting> <ScanConfig configID="-1" name="Special Example" """
        xml_request += """templateID="%s"></ScanConfig> </Site> </SiteSaveRequest> """ % template_id

        # Make connection and send xml request.
        print "[+] Creating the site."
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] Problem making SiteSaveRequest.")
        data = self.nx_response(response)

        # Parse data and look for what is needed.
        error = "[-] Response from the SiteSaveResponse returned an unexpected result."
        success_value = self.parse_data(data, 'SiteSaveResponse', error)

        # Check SiteSaveResponse success.
        self.check_value(success_value, "[-] Site creation error\n")

        # Wait for site to be created
        time.sleep(5)

        # Clean up
        con.close()

    def scan_site(self, siteID=None):
        """Scan a sites assets."""
        # Check if session_id is empty, get session if empty
        self.check_session()
        # Check for site-id.
        if(siteID != None):
            self.site_id = siteID

        # Build scan site request
        xml_request = """<SiteScanRequest session-id="%s" site-id="%s">
                        </SiteScanRequest>""" % (self.session_id, self.site_id)

        # Make connection and send xml request
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] Problem making SiteScanResponse")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        error = "[-] Response from the SiteScanResponse returned an unexpected result."
        success_value = self.parse_data(data, 'SiteScanResponse', error)

        # Check SiteScanResult success
        self.check_value(success_value, "[-] Site scan error Error\n")

        # Get scan-id and engine-id
        # Parse data and use what is needed
        try:
            dom = parseString(data)
            xmlTag = dom.getElementsByTagName('SiteScanResponse')[0]
            success_value = xmlTag.getAttribute("success")
            xmlTag2 = dom.getElementsByTagName('Scan')[0]
            self.scan_id = xmlTag2.getAttribute("scan-id")
            engine_id = xmlTag2.getAttribute("engine_id")
        except:
            print "[-] Response from the SiteScanResponse returned an unexpected result."
            exit(-1)

        # Check SiteScanResponse success
        self.check_value(success_value, "[-] Site scan error Error\n")

        # Clean up
        con.close()

    def check_scan(self, scanID=None):
        """Check with Nexpose until scan complete."""
        # Check if session_id is empty, get session if empty
        self.check_session()
        # Check for site-id.
        if(scanID != None):
            self.scan_id = scanID

        # Build xml request
        xml_request = """<ScanStatusRequest session-id="%s" scan-id="%s">
                        </ScanStatusRequest>""" % (self.session_id, self.scan_id)

        # Make connection and send request
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] Problem making ScanStatusRequest.")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        try:
            dom = parseString(data)
            xmlTag = dom.getElementsByTagName('ScanStatusResponse')[0]
            success_value = xmlTag.getAttribute("success")
            status = xmlTag.getAttribute("status")
        except:
            print "[-] Response from the ScanStatusResponse returned an unexpected result."
            exit(-1)

        # Check ScanStatusResponse success
        self.check_value(success_value, "[-] Error scanning\n")

        return status

    def generate_report(self, file_type, scanID=None):
        """Generate an adhoc report."""
        # Check if session_id is empty, get session if empty.
        self.check_session()
        # Check scanID
        if(scanID != None):
            self.scan_id = scanID

        # Build xml request
        xml_request = """<ReportAdhocGenerateRequest session-id="%s">
                        <AdhocReportConfig template-id="audit-report" format="%s">
                        <Filters>
                        <filter type="scan" id="%s"></filter></Filters>
                        </AdhocReportConfig>
                        </ReportAdhocGenerateRequest>
                        """ % (self.session_id, file_type, self.scan_id)
        headers = {"Content-type": "text/xml"}

        print "[+] Requesting an adhoc report."

        # Make connection and send xml request
        con = self.nx_connection()
        try:
            con.request("POST", "/api/1.1/xml", xml_request, headers)
            response = con.getresponse()
        except:
            print "[-] Response from the ReportAdhocGenerateRequest returned an unexpected result."
            exit(-1)

        if(DEBUG):
            print "[+] Response status: %s , Response reason: %s" % (response.status, response.reason)
        data = response.read()
        if(DEBUG):
            print "[+] Data received: %s " % data

        # Take the data look for what is needed
        # need to cut our base 64 data
        base64_identifier = "--AxB9sl3299asdjvbA"

        content_start = "Content-Transfer-Encoding: base64"
        start_of_base64 = data.rfind(content_start)
        end_of_base64 = data.rfind(base64_identifier)
        base64_data = data[start_of_base64+len(content_start)+2:end_of_base64]

        # Decode data to return
        decoded = base64.b64decode(base64_data)

        # Clean up
        con.close()

        return decoded

    def delete_site(self,siteID=None):
        """Delete a site and assets from Nexpose."""
        # Check if session_id is empty, get session if empty.
        self.check_session()
        # Check for site-id.
        if(siteID != None):
            self.site_id = siteID

        # Build xml request.
        xml_request = """<SiteDeleteRequest session-id="%s" site-id="%s">
                        </SiteDeleteRequest>""" % (self.session_id, self.site_id)

        # Make connection and send xml request.
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] Problem making SiteDeleteRequest")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        error = "[-] Response from the SiteDeleteResponse returned an unexpected result."
        success_value = self.parse_data(data, 'SiteDeleteResponse', error)

        # Check SiteSaveResponse success.
        self.check_value(success_value, "[-] Site deletion error\n")

        # Wait for site to be deleted.
        time.sleep(5)

        # Clean up
        con.close()

    def list_site(self):
        """List sites in Nexpose."""
        # Check if session_id is empty, get session if empty.
        self.check_session()

        # Build xml request.
        xml_request = """<SiteListingRequest session-id="%s">
                        </SiteListingRequest>""" % self.session_id

        # Make connection and send xml request.
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] Problem making SiteListingRequest")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        error = "[-] Response from the SiteListingResponse returned an unexpected result."
        success_value = self.parse_data(data, 'SiteListingResponse', error)

        # Check SiteSaveResponse success.
        self.check_value(success_value, "[-] Site listing error\n")

        # Clean up
        con.close()

    def vuln_list(self):
        """List vulnerabilities of Nexpose site."""
        # Check if session_id is empty, get session if empty.
        self.check_session()

        # Build xml request
        xml_request = """<VulnerabilityListingRequest sync-id="-1" session-id="%s">
                        </VulnerabilityListingRequest>""" % self.session_id

        # Make connection and send xml request.
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] VulnerabilityListingRequest")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        error = "[-] Response from the VulnerabilityListingRequest returned an unexpected result."
        success_value = self.parse_data(data, 'VulnerabilityListingRequest', error)

        # Check SiteSaveResponse success.
        self.check_value(success_value, "[-] Vulnerability listing error\n")

        # Clean up
        con.close()

    def scan_activity(self):
        """Check Nexpose scan activity."""
        # Check if session_id is empty, get session if empty.
        self.check_session()

        # Build xml request
        xml_request = """<ScanActivityRequest session-id="%s">
                        </ScanActivityRequest>""" % self.session_id

        # Make connection and send xml request.
        con = self.nx_connection()
        response = self.nx_request(con, xml_request, "[-] ScanActivityRequest")
        data = self.nx_response(response)

        # Parse data and look for what is needed
        error = "[-] Response from the ScanActivityRequest returned an unexpected result."
        success_value = self.parse_data(data, 'ScanActivityRequest', error)

        # Check SiteSaveResponse success.
        self.check_value(success_value, "[-] Scan activity error\n")

        # Clean up
        con.close()

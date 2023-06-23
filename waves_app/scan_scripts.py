import os
import re
import ssl
import json
import requests
import urllib.request
from urllib.request import Request
from .cpedictionary import technology_cpe_dictionary
from pyExploitDb import PyExploitDb

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
NVD_apikey = '90a924d1-78ba-4a33-827f-4ab19bfc35b4'
NVD_urlapi = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="
ExploitDB_url = "https://www.exploit-db.com/exploits/"
hdrs = {'apiKey' : '%s' % NVD_apikey}
pEdb = PyExploitDb()
pEdb.debug = False
pEdb.openFile()




#def ip_or_domain():
#    

def web_server_grabbing(ip):
    # Target Information
    # ip = "85.190.183.239"
    port = "80"
    target = "http://"+ip+":"+port

    vuln_list = []
    try:
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-agent', USER_AGENT)]
        #urllib.request.install_opener(opener)
        #gcontext = ssl.SSLContext()
        #response = urllib.request.urlopen(target, context=gcontext)
        response = urllib.request.urlopen(target)
        # print("Web Application Information")
        # print("----------------------------")
        # print("Scanning IP: " + ip + " on port: " + port)
        # print("----------------------------")
        for header, value in response.getheaders(): # For getting web headers
            cve=''
            description=''
            exploit_i=''
            exploit_link=''
            impact=''
            if header == ("Server" or "server"):
                webserver = ""
                webserver = value
                # print("Web Server: " + webserver)
                cpe_webserver = technology_cpe_dictionary[webserver]
                # print("CPE Detected: " + cpe_webserver)
                # print("----------------------------")
                response = requests.get(NVD_urlapi+cpe_webserver, headers=hdrs)
                data = json.loads(response.text)

                results = data["resultsPerPage"] # Total of CVEs detected

                for n in range(0, int(results)): # For getting eache CVE
                    cve = data["vulnerabilities"][n]["cve"]["id"] # CVE PARA PONER EN UNA LISTA 1
                    exploit = pEdb.searchCve(cve) 
                    if exploit != []:
                        exploit_i = exploit["description"] #  EXPLOIT PARA PONER EN UNA LISTA 2
                        exploit_link = ExploitDB_url+exploit["id"] # LINK DEL EXPLOIT PARA PONER EN UNA LISTA 4
                        # print("Available exploit detected! : " +exploit_i)
                        # print("Check the following link: " + exploit_link) 
                    # else:
                    #     print("Exploit not available yet")
                    description =data["vulnerabilities"][n]["cve"]["descriptions"][0]["value"] #  DESCRIPTION PARA PONER EN UNA LISTA 3
                    # print(description)
                    if "cvssMetricV2" in data["vulnerabilities"][n]["cve"]["metrics"]:
                        impact = str(data["vulnerabilities"][n]["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"]) #  IMPACT PARA PONER EN UNA LISTA 5
                        # print("CVSS v2 Score: " + impact)
                    else:
                        impact = str(data["vulnerabilities"][n]["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"])
                        # print("CVSS v3.1 Score: " + impact)
                    # print("----------------------------")
                    vuln = {
                        'cveCode': cve,
                        'description': description,
                        'exploit': exploit_i,
                        'exploitLink': exploit_link,
                        'impact': impact
                    }
                    vuln_list.append(vuln)
            if header == ("X-Powered-By" or "X-Generator"):
                webframework = ""
                webframework = value
                # print("Web Framework: " + webframework)
                cpe_webframework = technology_cpe_dictionary[webframework]
                # print("CPE Detected:" + cpe_webframework)
                # print("----------------------------")
                response = requests.get(NVD_urlapi+cpe_webframework, headers=hdrs)
                data = json.loads(response.text)

                results = data["resultsPerPage"]

                for n in range(0, int(results)):
                    cve = data["vulnerabilities"][n]["cve"]["id"] # CVE 1
                    # print(cve)
                    exploit = pEdb.searchCve(cve) 
                    if exploit != []:
                        exploit_i = exploit["description"] # EXPLOIT 2
                        exploit_link = ExploitDB_url+exploit["id"] #EXPLOIT URL 3
                        # print("Available exploit detected! : " +exploit_i)
                        # print("Check the following link: " + exploit_link) 
                    # else:
                    #     print("Exploit not available yet")
                    description=data["vulnerabilities"][n]["cve"]["descriptions"][0]["value"] #DESCRIPTION 4
                    # print(description) 
                    if "cvssMetricV2" in data["vulnerabilities"][n]["cve"]["metrics"]:
                        impact = str(data["vulnerabilities"][n]["cve"]["metrics"]["cvssMetricV2"][0]["impactScore"])
                        # print("CVSS v2 Score: " + impact) #IMPACT 5
                    else:
                        impact = str(data["vulnerabilities"][n]["cve"]["metrics"]["cvssMetricV31"][0]["impactScore"])
                    #     print("CVSS v3.1 Score: " + impact)
                    # print("----------------------------")
                    vuln = {
                        'cveCode': cve,
                        'description': description,
                        'exploit': exploit_i,
                        'exploitLink': exploit_link,
                        'impact': impact
                    }
                    vuln_list.append(vuln)
    except Exception as e:
        print(e)

    return vuln_list

if __name__ == '__main__':
    ip=''
    print(web_server_grabbing(ip))
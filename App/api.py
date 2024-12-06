import random
from flask import Flask, jsonify, request
import json
import requests
import whois
import random
import sys
import json
import time

import requests
import whois
from bs4 import BeautifulSoup as bsoup
from PIL import Image
from rich.table import Table
from rich import print as printc
app = Flask(__name__)
employees = [ { 'id': 1, 'name': 'Ashley' }, { 'id': 2, 'name': 'Kate' }, { 'id': 3, 'name': 'Joe' }]



class PhishDetector:

    def __init__(self,url: str):
            if url.startswith('http') and not self.get_domain_name(url).replace(".","").isdigit():
                self.url = url
                self.defanged_url = self.get_defanged_url(self.url)
                self.expanded_url = ""
                self.servers = ""
                self.target_webpage_screenshot = ""
                self.url_information = []
                self.information = {}
            else:
                return  "Invalid url specified" 
            
    @staticmethod
    def get_user_agent() -> str:
        # Generate a random user-agent
        with open('App/db/user_agents.db') as f:
            user_agents = f.readlines()
            return random.choice(user_agents)[:-1]
    
    def get_defanged_url(self, url: str) -> str:
        url_parts = url.split("/")
        scheme = url_parts[0].replace("https:", "hxxps").replace("http:", "hxxp")
        authority = self.get_domain_name(url).replace(".", "[.]")
        path = url_parts[-1]
        defanged_url = scheme + "[://]" + authority + "/" + path
        return defanged_url
        
    
    def get_whois_info(self, target_ip_address: str, verbosity: bool) -> None:
        try:
            target_whois_info = whois.whois(target_ip_address)
            if verbosity:
                target_whois_info = whois.whois(target_ip_address)
                for key,value in target_whois_info.items():
                    if key != "status":
                        if isinstance(value, list):
                            if 'date' in key:
                                self.information[key.capitalize()]=value[0]
                            else:
                                self.information[key.capitalize()]=value
                        else:
                            if value is None:
                                self.information[key.capitalize()]="N/A"
                            else:
                                self.information[key.capitalize()]=value
            else:
                whois_keys = ['name', 'emails', 'address', 'registrant_postal_code', 'registrar', 'creation_date', 'updated_date', 'expiration_date', 'country']
                for key,value in target_whois_info.items():
                    if key in whois_keys:
                        if isinstance(value, list):
                            if 'date' in key:
                                self.information[key.capitalize()]=value[0]
                            else:
                                self.information[key.capitalize()]=value
                        else:
                            if value is None:
                                self.information[key.capitalize()]="N/A"
                            else:
                                self.information[key.capitalize()]=value
            self.url_information.append({'Whois information': self.information})
        except Exception:
            self.url_information.append({'Whois information':'Unable to retrieve whois information!!'})
    
    
        

    def get_url_redirections(self, verbosity: bool) -> None:
        # Set the HTTP Request header
        headers = {
            'Accept-Encoding': 'gzip, deflate, br',
            'User-Agent': self.get_user_agent(),
            'Referer': 'https://iplogger.org/',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Check the target url's redirection(s)
        ip_logger_url_checker = "https://iplogger.org/url-checker/"
        with requests.Session() as session:
            response = session.get(ip_logger_url_checker, headers=headers)
            # Mimic an authentic request (Avoid detection)
            if 'Set-Cookie' in response.headers:
                headers['Cookie'] = response.headers['Set-Cookie']
            if 'Cache-Control' in response.headers:
                headers['Cache-Control'] = response.headers['Cache-Control']
            if 'Last-Modified' in response.headers:
                headers['If-Modified-Since'] = response.headers['Last-Modified']
            params = {"url": self.url}
            response = session.get(ip_logger_url_checker, headers=headers, params=params)
            self.servers = list() # List of dictionaries
            if response.ok:
                soup = bsoup(response.content, 'html.parser')
                servers_info = soup.find_all("div", class_="server-info")
                for server_info in servers_info:
                    server_items = server_info.find_all("div", class_="server-item")
                    server_antivirus = server_info.find("div", class_="server-antivirus")
                    server_next = server_info.find("div", class_="server-next")
                    server_item_info = list()
                    server_dict = dict() # Dictionary containing information about each server from which the request goes through
                    for server_item in server_items:
                        for item in server_item:
                            if item != "\n":
                                server_item_info.append(item)
                        if server_item_info[0].string == "Host":
                            server_dict[server_item_info[0].string] = server_item_info[-1].string
                            self.expanded_url = server_item_info[-1].string
                        elif server_item_info[0].string == "IP address":
                            server_dict[server_item_info[0].string] = server_item_info[-1].contents[-2].string
                            self.target_ip_address = server_item_info[-1].contents[-2].string
                        else:
                           server_dict[server_item_info[0].string] = server_item_info[-1].string
                        server_item_info.clear()
                    server_dict["Status code"] = server_next.contents[1].string
                    server_dict["Google Safe Browsing Database"] = server_antivirus.contents[1].string
                    self.servers.append(server_dict)
                
                # Display url's information based on the verbosity
                number_of_redirections = len(self.servers)
                if verbosity and number_of_redirections > 1:
                    for server_index in range(number_of_redirections):
                        self.url_information.append({
                            'Redirections':{
                            'Host':self.servers[server_index]['Host'],
                            'Status code': self.servers[server_index]['Status code'],
                            'IP address': self.servers[server_index]['IP address'],
                            'Country by IP':self.servers[server_index]['Country by IP']
                            }})

                elif number_of_redirections > 1:
                    self.url_information.append({
                            'Redirections':{
                            'Source URL':self.url,
                            'Source Domain': self.get_domain_name(self.url),
                            'Destination URL': self.expanded_url,
                            'Destination Domain':self.get_domain_name(self.expanded_url)
                            }})
                else:
                    self.url_information.append({
                            'Redirections':{
                            'Found':'N/A',
                            }})
    
    
                
    
   
    
    def get_domain_name(self, url: str) -> str:
        url_parts = url.split('/')
        return url_parts[2]

    def check_tracking_domain_name(self) -> None:
        target_domain_name = self.get_domain_name(self.url)
        with open("App/db/ip_tracking_domains.json") as f:
            data = json.load(f)
        for ip_tracker_provider,ip_tracking_domain in data.items():
            if ip_tracking_domain == target_domain_name:
                self.url_information.append({ 'IP tracking domain name own by' :ip_tracker_provider})
                break
        else:
            self.url_information.append({ 'IP tracking domain name own by' :"N/A"})
    
    def check_url_shortener_domain(self) -> None:
        target_domain_name = self.get_domain_name(self.url)
        with open('C:/Users/tusha/OneDrive/Desktop/github/safeurl-check/App/db/url_shortener_domains.db') as f:
            url_shortener_domains = f.readlines()
            for url_shortener_domain in url_shortener_domains:
                if url_shortener_domain[:-1] == target_domain_name:
                    self.url_information.append(

                        {
                            'Url found in Url Shortener domain database':
                            'Yes',
                            'Shortened url':
                            self.defanged_url
                        }
                    )
                    break
            else:
               self.url_information.append({
                            'Url found in Url Shortener domain database':
                            'No',
                        })
    
    



@app.route('/url',methods=['GET'])
def hello():
    url = request.args.get('url')
    verbosity = request.args.get('verbosity')
    phish_detector =PhishDetector(url)
    phish_detector.url_information.append({'Target URL': phish_detector.defanged_url})
    if phish_detector.url != phish_detector.expanded_url and len(phish_detector.expanded_url) > 60:
       phish_detector.url_information.append({'Destination url:': phish_detector.expanded_url})
    phish_detector.get_url_redirections(verbosity)
    phish_detector.check_url_shortener_domain()
    phish_detector.check_tracking_domain_name()
    phish_detector.get_whois_info(url, verbosity)

    return jsonify(phish_detector.url_information)
    
    # except Exception:
    #         return "Unable to retrieve whois information!!"
        


if __name__ == '__main__':
   app.run(port=5000)
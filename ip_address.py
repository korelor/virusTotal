import ipaddress
from pymongo import MongoClient
import requests
import os
from dotenv import load_dotenv
from prettytable import PrettyTable

# connet to  mongodb 
def conn_mongo():
    mg_uri          = "mongodb://korelor:mongo@localhost:27017/"
    mg_client       = MongoClient(mg_uri)
    db_vt           = mg_client["virusTotal"]
    collection_ip   = db_vt["maliciousIPs"]
    return collection_ip
    
# check the ip in virus total 
def check_virusTotal(ip):
    load_dotenv()
    
    url     = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
    headers = {
        "x-apikey": os.environ['VT_API_KEY']
    }
    res = requests.get(url, headers=headers)
    return res.json()["data"]

# show the result in terminal
def show_result(data):
    table             = PrettyTable()
    table.field_names = ["IP address", "Country", "Malicious", "Suspicious", "Undetected", "Harmless"]
    table.add_row([data["id"],
                   data["attributes"]["country"],
                   data["attributes"]["last_analysis_stats"]["malicious"],
                   data["attributes"]["last_analysis_stats"]["suspicious"],
                   data["attributes"]["last_analysis_stats"]["undetected"],
                   data["attributes"]["last_analysis_stats"]["harmless"],
                   ])
    print(table)

def main():
    collection_ip = conn_mongo()
    while True:
        ip = input("\nEnter the IP address (to exit, enter the q):\n")
        if ip == 'q':
            return
        
        try:
            # validating input as ip address
            ipaddress.ip_address(ip)
            data = collection_ip.find_one({"id": ip})
            if data == None:
                print("\nUsing virus total api...")
                data = check_virusTotal(ip)
                collection_ip.insert_one(data)
            
            show_result(data)
        except ValueError:
            print(f'{ip!r} does not appear to be an IPv4 or IPv6 address, Please enter the corrent ip format :)')

if __name__ == "__main__":
    main()
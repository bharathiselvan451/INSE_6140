import pandas as pd # type: ignore
import requests # type: ignore
import time
import json as js
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
from datetime import date
import os
from subprocess import call
import hashlib
from collections import ChainMap
from tqdm import tqdm
import math
from itertools import chain




wpfence = pd.read_csv("/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/wordfence.csv")


d_check = pd.read_csv("/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/dependency-check-report.csv")

packages = d_check["DependencyPath"].str.contains("/Applications/XAMPP/xamppfiles/htdocs/scan/composer.lock")

wp_dependencies = d_check[packages]

set_1 = set()
remover = set()
json_data = []


i = 0
years = set()
year = 2002
for x in wp_dependencies["CVE"].unique():
    set_1.add(x)
    years.add(int(str(x).split('-')[1]))

current_date = date.today()
current_year = current_date.year

f = open("/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/wpscan.json")
data = js.loads(f.read())

final_set= set()

a = 0

set_2 = set()
while(a<len(data["version"]["vulnerabilities"])):
    try:
        add = ("CVE-"+data["version"]["vulnerabilities"][a]["references"]["cve"][0])
        set_2.add(add)
    except:
       pass


    a = a+1



for key in data["plugins"].keys():
    b = 0
    while(b<len(data["plugins"][key]["vulnerabilities"])):
        try:
            add = ("CVE-"+data["plugins"][key]["vulnerabilities"][b]["references"]["cve"][0])
            set_2.add(add)
        except:
            pass
        
        b = b+1


set_3 = set()
set_3 = (wpfence[wpfence.columns[0]]).unique()




#print(set_3)

final_set = set_2.union(set_1,set_3)
#print(final_set)

print("initial length ",len(final_set))


while (year<=current_year):
      
          
      url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+str(year)+".meta"
      resp = requests.get(url)
      #print(resp.content.decode('utf-8').split(":")[8])

      with open("/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/jsons/nvdcve-1.1-"+str(year)+".json", 'rb') as f:
         bytes = f.read() # read entire file as bytes
         readable_hash = hashlib.sha256(bytes).hexdigest()
      if(resp.content.decode('utf-8').split(":")[8].strip() != readable_hash.upper()):
          url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+str(year)+".json.zip"
          resp = urlopen(url)
          myzip = ZipFile(BytesIO(resp.read()))
          myzip.extractall(path='/tmp/')
          f = open('/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/jsons/nvdcve-1.1-'+str(year)+'.json')
          data = js.loads(f.read())

      year = year+1
      


def finder(year,final_set,remover):
     
    f = open("/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/jsons/nvdcve-1.1-"+str(year)+".json")
    data = js.loads(f.read())
    #print("-------------------------")
    #print("year: ",year)
    #print(len(final_set))
    json = []

    for x in final_set:
       
        SCORE = ""
        cvss = ""
        impact = ""
        try:
            if((int(str(x).split('-')[1]))!=int(year)):
             continue
        except:
             pass
        i = 0
        j = 1
        length = len(data["CVE_Items"])
        while(i<length):
            
             
                 
                 
             if(str(data["CVE_Items"][i]['cve']['CVE_data_meta']['ID']).strip()==str(x).strip()):
                  dict = {}
                  try:
                       
                       dict["CVE"] = x
                       dict["NIST score"] = data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                       dict["Scoring System"] = "cvssV3"
                       dict["Impact"] = data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
                       if(x in set_1):
                           dict["Dependency-check"] = "positive"
                       else:
                           dict["Dependency-check"] = "Negative"
                       if(x in set_2):
                           dict["Wp-scan"] = "positive"
                       else:
                           dict["Wp-scan"] = "Negative"
                       if(x in set_3):
                           dict["Wordfence"] = "positive"
                       else:
                           dict["Wordfence"] = "Negative"
                       json.append(dict)
                       remover.add(x)
                       #print("-------------------------")

                       break
                      
                       
                  except:
                    try:
                        
                        dict["CVE"] = x
                        dict["NIST score"] = data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        dict["Scoring System"] = "cvssV2"
                        dict["Impact"] = data["CVE_Items"][i]["impact"]["baseMetricV2"]["severity"]
                        if(x in set_1):
                           dict["Dependency-check"] = "positive"
                        else:
                           dict["Dependency-check"] = "Negative"
                        if(x in set_2):
                           dict["Wp-scan"] = "positive"
                        else:
                           dict["Wp-scan"] = "Negative"
                        if(x in set_3):
                           dict["Wordfence"] = "positive"
                        else:
                           dict["Wordfence"] = "Negative"
                        json.append(dict)
                        remover.add(x)
                        #print("-------------------------")


                        break

                    except:
                        dict["CVE"] = x
                        dict["warning"] = "details not available"
                        json.append(dict)

                    
             i = i+1
                  
    return json

     
for y in years:
    json_data.append(finder(y,final_set,remover))
    final_set = final_set-remover
    remover.clear()
   

with open('/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/result_data.json', 'w', encoding='utf-8') as f:
    js.dump(json_data, f, ensure_ascii=False, indent=4)    

def Sonar_results():
    url = 'http://localhost:9000/api/hotspots/search?projectKey=local'
    myToken = 'squ_69119ff06b2e66e8cf603f90cec26ca47b60a957'

    session = requests.Session()
    session.auth = myToken, ''

    call = getattr(session, 'get')
    res = call(url)
    print(res.status_code)

    binary = res.content
    output = js.loads(binary)

    with open('/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/SonarQube_results.json', 'w', encoding='utf-8') as f:
      js.dump(output, f, ensure_ascii=False, indent=4)                

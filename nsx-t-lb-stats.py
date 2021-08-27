#!/usr/bin/env python

"""
The BSD-2 license (the "License") set forth below applies to this script.
You may not use this file except in compliance with the License.

BSD-2 License

Redistribution and use in source and binary forms, with or
without modification, are permitted provided that the following
conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the
    following disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the
    following disclaimer in the documentation and/or other
    materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

import json
from datetime import datetime
import csv
import time
import ssl
import requests
import urllib3


"""
This python script will gather the statistics (CPS, L4 Bytes, TPS, RPS & SSL Bytes)from all NSX-T load balancers in a given local manager using the policy API.  The
script sumarizes the total for each statistic for each sample period and writes a record to total-stats.csv in the current directory.  To identify the peak of each 
stat open the total-stats.csv and sort each colum decending.  The scrpt also itterates through all the virtual services within each load balancer and keeps the peak
of each metric.  The peak metrics are written to peak-stats-per-vs.txt in the current directory.  Both files are written out during each sample period so if the script
dies or is terminated early the partial collection can still be used. A summary of the total stats is written to the console ever execution interval so that you can 
monitor the progress of the script.

APIs used:

This API is called once per execution of the script.
GET /policy/api/v1/infra/lb-services

This API is called once per load balancer every execution_interval.
GET /policy/api/v1/infra/lb-services/<lb-service-id>/statistics

This API is called once every time a new virtual server is identified in the load balancer statistics.  
GET /policy/api/v1/infra/lb-virtual-servers 

"""

def is_json_key_present(json, key):
    try:
        buf = json[key]
    except KeyError:
        return False
    return True

def checkKeyValuePairInList(vs_list, key, value):
    vsCount=len(vs_list)
    for i in range(0,vsCount):
        if vs_list[i][key] == value:
            return i
    return -1

def checkUpdateStat (new_stat, cur_stat):
    if new_stat>cur_stat:
        return new_stat
    else:
        return cur_stat

def main():
    #TODO: Update with your url and credentials
    nsx_mgr = 'https://nsx-t-mgr.far-away.galaxy'
    username='audit'
    password='VMware12345^'

    #TODO: Specify the desired collection time in days.  
    desired_collection_days=1
    execution_interval=5
   
    
    itterations=int(desired_collection_days*24*60*60/execution_interval)
    
    vs_list = []

    #Setup connection to the NSX Manager
    ssl._create_default_https_context = ssl._create_unverified_context
    s = requests.Session()
    s.verify = False
    s.auth = (username, password)
    urllib3.disable_warnings()
    
    #Setup the total stats file.  This file has the sum of all the stats along with a date stamp.  This is written out as a csv so you can easily sort to find the peak of each value.
    total_stats_file = open("./total-stats.csv", "w")
    fieldnames=["timestamp", "lb_count", "vs_count", "cps", "l4_bytes", "tps", "rps","ssl_bytes"]
    total_stats_writer = csv.DictWriter(total_stats_file, fieldnames=fieldnames)
    total_stats_writer.writeheader()

    start_message="Started collection at {0} for {1} samples every {2} seconds.".format(datetime.now(),itterations, execution_interval)
    print(start_message)

    #Main loop to collect data every execution_interval for the itterations caclulated to reach the desired_collection_days 
    for sample in range(0,itterations):
        
        #get the load balancer inventory
        upath = '/policy/api/v1/infra/lb-services'
        lb_json = s.get(nsx_mgr + upath).json()
        lb_count = len(lb_json["results"])

        #initialize the total stats
        total_stats={"timestamp":str(datetime.now()),"lb_count":lb_count,"vs_count":0,"cps":0,"l4_bytes":0,"tps":0,"rps":0,"ssl_bytes":0}

        #Loop through the load balancers
        for lb in range(0,lb_count):
            #Collect the lb_id that is required to pull the statistics
            lb_id=lb_json["results"][lb]["id"]
            
            #Get the stats for the lb_id
            upath = '/policy/api/v1/infra/lb-services/' + lb_id + '/statistics?source=realtime'
            stats_json = s.get(nsx_mgr + upath).json()

            #Grab the virtual server stats array
            vs_stats_json=stats_json["results"][0]["virtual_servers"]
            vs_count = len(vs_stats_json)
            total_stats["vs_count"]+= vs_count
            #Loop through the virtual servers
            for vs in range(0,vs_count):
                
                #if the virtual server doesn't already exist then lookup vs_id and check if it is configured for SSL
                row=checkKeyValuePairInList(vs_list,'virtual_server_path',vs_stats_json[vs]["virtual_server_path"])
                if row == -1:
                    #Get the config for the virtual server vs_id and determine if it is terminating ssl based on the existance of a client_ssl_profile_binding
                    upath = "/policy/api/v1" + vs_stats_json[vs]["virtual_server_path"]
                    vs_json = s.get(nsx_mgr + upath).json()
                    vs_id = vs_json["id"]
                    is_SSL = is_json_key_present(vs_json, "client_ssl_profile_binding")
                else:
                    #Otherwise use the values in the vs_list for the row
                    is_SSL=vs_list[row]["is_SSL"]
                    vs_id=vs_list[row]["vs_id"]

                #Initialize the statistics
                cps=0;l4_bytes=0;tps=0;ssl_bytes=0;rps=0

                #use the current stats rate to populate the metrics based on if this is SSL or non SSL. 
                l4_bytes=vs_stats_json[vs]["statistics"]["bytes_in_rate"] + vs_stats_json[vs]["statistics"]["bytes_out_rate"]
                cps=vs_stats_json[vs]["statistics"]["http_request_rate"]            
                if is_SSL :
                    ssl_bytes = vs_stats_json[vs]["statistics"]["bytes_in_rate"] + vs_stats_json[vs]["statistics"]["bytes_out_rate"]
                    tps = vs_stats_json[vs]["statistics"]["current_session_rate"]
                    rps = vs_stats_json[vs]["statistics"]["http_request_rate"]
                
                #Update total stats
                total_stats["cps"]+= cps
                total_stats["l4_bytes"]+= l4_bytes
                total_stats["tps"]+= tps
                total_stats["rps"]+= rps
                total_stats["ssl_bytes"]+= ssl_bytes

                #if the virtual server didn't exist in vs_list then append it to the list.  If it did exist check each new stat and keep the peak stat.
                if row == -1:
                    #Build the stats json
                    statistcs={'cps': cps,'l4_bytes': l4_bytes,'tps': tps,'rps': rps,'ssl_bytes': ssl_bytes}
                    vs_stats={"virtual_server_path":vs_stats_json[vs]["virtual_server_path"],'vs_id': vs_id,'is_SSL':is_SSL,'statistics':statistcs}    
                    vs_list.append(vs_stats)
                else:
                    vs_list[row]["statistics"]["cps"]= checkUpdateStat(cps,vs_list[row]["statistics"]["cps"])
                    vs_list[row]["statistics"]["l4_bytes"] = checkUpdateStat(l4_bytes,vs_list[row]["statistics"]["l4_bytes"])
                    vs_list[row]["statistics"]["tps"] = checkUpdateStat(tps,vs_list[row]["statistics"]["tps"])
                    vs_list[row]["statistics"]["rps"] = checkUpdateStat(rps,vs_list[row]["statistics"]["rps"])
                    vs_list[row]["statistics"]["ssl_bytes"] = checkUpdateStat(ssl_bytes,vs_list[row]["statistics"]["ssl_bytes"])
                    #print(vs_list[row])
        
        #After looping through all the load balancers and virtual servers append the total stats with a timestamp. 
        total_stats_writer.writerow(total_stats)
        
        #Write the summary stats to the screen so we know the program is working
        print("Sample {0}/{1} - {2}".format(sample,itterations,total_stats))
        
        #Overwrite the peak stats at each interval so we have the peaks in the event the program doesn't complete through the desired runtime.
        peak_stats_file = open("./peak-stats-per-vs.txt", "w")
        vsCount=len(vs_list)
        peak_stats_file.write(start_message + "This file contains the peak value of each metric observed on each virtual service at any sample period. \n")
        total_cps=0;total_l4_bytes=0;total_tps=0;total_rps=0;total_ssl_bytes=0
        for row in range(0,vsCount):
            peak_stats_file.write(json.dumps(vs_list[row]) + "\n")
            total_cps += vs_list[row]["statistics"]["cps"]
            total_l4_bytes += vs_list[row]["statistics"]["l4_bytes"]
            total_tps += vs_list[row]["statistics"]["tps"]
            total_rps += vs_list[row]["statistics"]["rps"]
            total_ssl_bytes += vs_list[row]["statistics"]["ssl_bytes"]
        peak_stats_file.write("Summary Peak Virtual Server Stats {0} hours.\n".format(execution_interval*itterations/60/60))
        peak_stats_file.close()
        time.sleep(execution_interval)
    total_stats_file.close()
    
if __name__ == "__main__":
    main()


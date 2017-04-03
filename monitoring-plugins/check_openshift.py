#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Florian Lambert <flambert@redhat.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Requirments: python
#
# Pods : Allow you to check if pods registry and router are running.
# Nodes : Check if nodes status isn't Running

import sys
import argparse
import subprocess
import requests
import re

# Disable warning for insecure https
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from requests.exceptions import ConnectionError

VERSION = '1.4'

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

STATE_TEXT = ['Ok', 'Warning', 'Critical', 'Unknown']

STATE = STATE_OK
OUTPUT_MESSAGE = ''
OUTPUT_MESSAGE_PERFDATA = ''

PARSER = argparse.ArgumentParser(description='Openshift check pods')
PARSER.add_argument("-proto", "--protocol", type=str,
                    help='Protocol openshift (Default : https)',
                    default="https")
PARSER.add_argument("-api", "--base_api", type=str,
                    help='Url api and version (Default : /api/v1)',
                    default="/api/v1")
PARSER.add_argument("-H", "--host", type=str,
                    help='Host openshift (Default : 127.0.0.1)',
                    default="127.0.0.1")
PARSER.add_argument("-P", "--port", type=str,
                    help='Port openshift (Default : 8443)',
                    default=8443)
PARSER.add_argument("-u", "--username", type=str,
                    help='Username openshift (ex : sensu)')
PARSER.add_argument("-p", "--password", type=str,
                    help='Password openshift')
PARSER.add_argument("-to", "--token", type=str,
                    help='File with token openshift (like -t)')
PARSER.add_argument("-tf", "--tokenfile", type=str,
                    help='Token openshift (use token or user/pass')
PARSER.add_argument("--check_nodes", action='store_true',
                    help='Check status of all nodes')
PARSER.add_argument("--check_pods", action='store_true',
                    help='Check status of pods ose-haproxy-router and ose-docker-registry')
PARSER.add_argument("--exclude_pods", type=str,nargs='+', default=[],
                    help='Exclude pods where the name contains the string passed in argument, find in the field deploymentconfig labels str,str,str ')
PARSER.add_argument("--exclude_pvs", type=str,nargs='+', default=[],
                    help='Exclude pvs where the name contains the value passed in argument')
PARSER.add_argument("--check_pvs", action='store_true',
                    help='Check status of persistent volume  ')     
PARSER.add_argument("--check_scheduling", action='store_true',
                    help='Check if your nodes is in SchedulingDisabled stat. Only warning')
PARSER.add_argument("--check_labels", action='store_true',
                    help='Check if your nodes have your "OFFLINE" label. Only warning (define by --label_offline)')
PARSER.add_argument("--warn_avai_pv", type=str,
                    help='Warning threshold for "Available" Persistent Volumes',
                    default=1)
PARSER.add_argument("--crit_avai_pv", type=str,
                    help='Critical threshold for "Available" Persistent Volumes',
                    default=0)
PARSER.add_argument("--warn_relea_pv", type=str,
                    help='Warning threshold for "Released" Persistent Volumes',
                    default=1)
PARSER.add_argument("--crit_relea_pv", type=str,
                    help='Critical threshold for "Released" Persistent Volumes',
                    default=0)
PARSER.add_argument("--label_offline", type=str,
                    help='Your "OFFLINE" label name (Default: retiring)',
                    default="retiring")
PARSER.add_argument("--check_project_labels", action='store_true',
                    help='Check if your projects have the required labels set (define by --required_project_labels)')
PARSER.add_argument("--required_project_labels", type=str, nargs='+',
                    help='The names of your required project labels as space separated list')
PARSER.add_argument("-v", "--version", action='store_true',
                    help='Print script version')
ARGS = PARSER.parse_args()


class Openshift(object):
    """
    A little object for use REST openshift v3 api
    """

    def __init__(self,
                 proto='https',
                 host='127.0.0.1',
                 port=8443,
                 username=None,
                 password=None,
                 token=None,
                 tokenfile=None,
                 debug=False,
                 verbose=False,
                 namespace='default',
                 base_api='/api/v1',
                 warn_avai_pv=None,
                 crit_avai_pv=None,
                 warn_relea_pv=None,
                 crit_relea_pv=None,
                 exclude_pods=None,
                 exclude_pvs=None):

        self.os_STATE = 0
        self.os_OUTPUT_MESSAGE = ''
        self.os_OUTPUT_MESSAGE_PERFDATA = ''
        self.proto = proto
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.debug = debug
        self.verbose = verbose
        self.namespace = namespace
        self.warn_avai_pv = warn_avai_pv
        self.crit_avai_pv = crit_avai_pv
        self.warn_relea_pv = warn_relea_pv
        self.crit_relea_pv = crit_relea_pv
        self.exclude_pods = exclude_pods
        self.exclude_pvs = exclude_pvs
        
        # Remove the trailing / to avoid user issue
        self.base_api = base_api.rstrip('/')

        if token:
            self.token = token
        elif tokenfile:
            self.token = self._tokenfile(tokenfile)
        else:
            self.token = self._auth()

    def _auth(self):
        cmd = ("oc login %s:%s -u%s -p%s --insecure-skip-tls-verify=True 2>&1 > /dev/null"
               % (self.host, self.port, self.username, self.password))
        subprocess.check_output(cmd, shell=True)

        cmd = "oc whoami -t"
        stdout = subprocess.check_output(cmd, shell=True)

        return stdout.strip()

    def _tokenfile(self, tokenfile):
        try:
            f = open(tokenfile, 'r')
            return f.readline().strip()
        except IOError:
            self.os_OUTPUT_MESSAGE += ' Error: File does not appear to exist'
            self.os_STATE = 2
            return "tokenfile-inaccessible"

    def get_json(self, url):

        headers = {"Authorization": 'Bearer %s' % self.token}
        try:
            r = requests.get('https://%s:%s%s' % (self.host, self.port, url),
                             headers=headers,
                             verify=False)  # don't check ssl
            parsed_json = r.json()
        except ValueError:
            print "%s: GET %s %s" % (STATE_TEXT[STATE_UNKNOWN], url, r.text[:200])
            sys.exit(STATE_UNKNOWN)
        except ConnectionError as e:
            print "https://%s:%s%s - %s" % (self.host, self.port, url, e)
            sys.exit(STATE_CRITICAL)

        return parsed_json

    def get_scheduling(self):

        self.os_OUTPUT_MESSAGE += ' Nodes: '

        api_nodes = '%s/nodes' % self.base_api
        parsed_json = self.get_json(api_nodes)

        # Return unknow if we can't find datas
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find nodes data in the response.'
            return

        all_nodes_names = ''
        for item in parsed_json["items"]:
            all_nodes_names += '%s ' % item["metadata"]["name"]

            # print item["metadata"]["name"]
            # print item["status"]["addresses"][0]["address"]
            # print item["status"]["conditions"][0]["type"]
            # print item["status"]["conditions"][0]["status"]
            # print item["status"]["conditions"][0]["reason"]

            try:
                if item["spec"]["unschedulable"]:
                    self.os_STATE = 1
                    self.os_OUTPUT_MESSAGE += ("%s/%s: [SchedulingDisabled] "
                                               % (item["metadata"]["name"], item["status"]["addresses"][0]["address"]))
            except KeyError:
                continue

        if self.os_STATE == 0:
            self.os_OUTPUT_MESSAGE += "%s [Schedulable]" % (all_nodes_names)

    def get_nodes(self):

        self.os_OUTPUT_MESSAGE += ' Nodes: '

        api_nodes = '%s/nodes' % self.base_api
        parsed_json = self.get_json(api_nodes)

        # Return unknow if we can't find datas
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find nodes data in the response.'
            return        
        all_nodes_names = ''
        for item in parsed_json["items"]:
            all_nodes_names += '%s ' % item["metadata"]["name"]

            # print item["metadata"]["name"]
            # print item["status"]["addresses"][0]["address"]
            # print item["status"]["conditions"][0]["type"]
            # print item["status"]["conditions"][0]["status"]
            # print item["status"]["conditions"][0]["reason"]

            status_ready = {}
            for condition in item["status"]["conditions"]:
                if condition["type"] == "Ready":
                    status_ready = condition
                    break

            # if status not ready
            if status_ready["status"] != "True":
                self.os_STATE = 2
                self.os_OUTPUT_MESSAGE += "%s/%s: [%s %s] " % (item["metadata"]["name"],
                                                               item["status"]["addresses"][0]["address"],
                                                               status_ready["status"],
                                                               status_ready["reason"])

        if self.os_STATE == 0:
            self.os_OUTPUT_MESSAGE += "%s [Ready]" % (all_nodes_names)

    def get_pods(self, namespace=None,exclude_pods=[]):
             
        if namespace:
            self.namespace = namespace
        api_pods = '%s/namespaces/%s/pods' % (self.base_api, self.namespace)

        parsed_json = self.get_json(api_pods)
        pods = {}
        podc ={}

        if self.base_api == '/api/v1beta3':
            status_condition = 'Condition'
        else:
            status_condition = 'conditions'

        # Return unknow if we can't find datas
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find nodes data in the response.'
            return

        for item in parsed_json["items"]:            
            podc.setdefault('pod',[])
            if exclude_pods:                
                for search in  exclude_pods:
                    print 'search:'+search+'-> pod:'+item["metadata"]["name"]
                    exclude = re.match(search, item["metadata"]["name"])                    
                    if exclude:
                        print 'result:'+exclude    
                        continue                    
                    try:                        
                        if item["status"][status_condition][0]["status"] != "True":
                            if 'deploymentconfig' in item["metadata"]["labels"].keys():
                                pods[item["metadata"]["labels"]["deploymentconfig"]] = "%s: [%s] " % (item["metadata"]["name"],
                                                                                                      item["status"]["phase"],
                                                                                                      item["status"][status_condition][0]["status"])
                                self.os_STATE = 2
                        else:
                            if 'deploymentconfig' in item["metadata"]["labels"].keys():
                                pods[item["metadata"]["labels"]["deploymentconfig"]] = "%s: [%s] " % (item["metadata"]["name"],
                                                                                                 item["status"]["phase"])
                            podc['pod'].append(1)                                                                     
                    except:
                        pass
            else:
                try:
                    if item["status"][status_condition][0]["status"] != "True":
                        if 'deploymentconfig' in item["metadata"]["labels"].keys():
                            pods[item["metadata"]["labels"]["deploymentconfig"]] = "%s: [%s] " % (item["metadata"]["name"],
                                                                                                      item["status"]["phase"],
                                                                                                      item["status"][status_condition][0]["status"])
                            self.os_STATE = 2
                    else:
                        if 'deploymentconfig' in item["metadata"]["labels"].keys():
                            pods[item["metadata"]["labels"]["deploymentconfig"]] = "%s: [%s] " % (item["metadata"]["name"],
                                                                                                 item["status"]["phase"])
                        podc['pod'].append(1)
                except:
                    pass
                        
        
        for key,values in podc.items():                
                self.os_OUTPUT_MESSAGE_PERFDATA +=  'PODS=%spod(s);0;100' % (sum(values))
                self.os_OUTPUT_MESSAGE += ' %s PODS ' % sum(values)
                
        registry_dc_name = 'docker-registry'
        router_dc_name = 'router'

        if registry_dc_name in pods:
            self.os_OUTPUT_MESSAGE += pods[registry_dc_name]
        else:
            self.os_OUTPUT_MESSAGE += '%s [Missing] ' % registry_dc_name
            self.os_STATE = 2

        if router_dc_name in pods:
            self.os_OUTPUT_MESSAGE += pods[router_dc_name]
        else:
            self.os_OUTPUT_MESSAGE += '%s [Missing] ' % router_dc_name
            self.os_STATE = 2
 
 
 
    def get_pvs(self,warn_avai_pv,crit_avai_pv,warn_relea_pv,crit_relea_pv,exclude_pvs=[]):

        self.os_OUTPUT_MESSAGE += ' PV '

        api_pvs = '%s/persistentvolumes' % self.base_api

        parsed_json = self.get_json(api_pvs)

        pvs = {}

        if self.base_api == '/api/v1beta3':
            status_condition = 'Condition'
        else:
            status_condition = 'conditions'
  
  # Return unknow if we can't find datas
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find nodes data in the response.'
            return        
        pvs={}
        pvsc={}               
        avl=0
        bnd=0
        rls=0          
        for item in parsed_json["items"]:
            capacity = re.findall( r'\d+', item["spec"]["capacity"]["storage"], re.MULTILINE)
            pvs[item["metadata"]["name"]] = "%s;%d" % (item["status"]["phase"],
                                                                                int(capacity[0]))
            pvsc.setdefault(int(capacity[0]),[])                                                                                                                                                       
            try:
                if item["status"]["phase"] == 'Available':                                                                                   
                        avl += 1
                        pvsc[int(capacity[0])].append(1)                                                                        
                elif item["status"]["phase"] == 'Bound':
                        bnd += 1           
                elif item["status"]["phase"] == 'Released':
                        rls += 1                        
            except:
                pass
        
        #Remove PV in array with argument exclude_pvs
        for remove_pvs in exclude_pvs:             
             if int(remove_pvs) in pvsc:
                del pvsc[int(remove_pvs)]                  
        
        for key,values in pvsc.items():
            #print values
            if  int(crit_avai_pv) >= sum(values):  # CRITICAL                             
                self.os_OUTPUT_MESSAGE_PERFDATA +=  ' PV(%s)=%spv;0;100' % (key,sum(values))                
                self.os_STATE = 2
                self.os_OUTPUT_MESSAGE += '%s(G) %s Not Available ' % (key,sum(values))                
            elif int(warn_avai_pv) >= sum(values):  # WARNING                                
                 self.os_OUTPUT_MESSAGE_PERFDATA +=  ' PV(%s)=%spv;0;100' % (key,sum(values))
                 self.os_STATE = 1            
                 self.os_OUTPUT_MESSAGE += '%s(G) %s Not Available ' % (key,sum(values))                 
            else:                              
                self.os_OUTPUT_MESSAGE_PERFDATA +=  ' PV(%s)=%spv;0;100' % (key,sum(values))                
                if int(crit_relea_pv) or int(warn_relea_pv):
                    if int(crit_relea_pv) <= rls: # CRITICAL
                        self.os_STATE = 2
                        self.os_OUTPUT_MESSAGE += '%s Release ' % rls
                    elif int(warn_relea_pv) <= rls: # WARNING
                        self.os_STATE = 1
                        self.os_OUTPUT_MESSAGE += '%s Release ' % rls
                    else:
                        if self.os_STATE == 2:                        
                            self.os_STATE = 2 
                        else:
                            self.os_STATE = 0                       
                        self.os_OUTPUT_MESSAGE += '%s(G) %s Available ' % (key,sum(values))
                else: 
                    if self.os_STATE == 2:                        
                        self.os_STATE = 2 
                    else:
                        self.os_STATE = 0    
                    self.os_OUTPUT_MESSAGE += '%s(G) Available ' % key
        self.os_OUTPUT_MESSAGE_PERFDATA += ' Available=%spv;0;100 Release=%spv;0;100 Bound=%spv;0;100' % (avl,rls,bnd)
        
       
            
    def get_labels(self, label_offline):

        self.os_OUTPUT_MESSAGE += ' Nodes: '

        api_nodes = '%s/nodes' % self.base_api
        parsed_json = self.get_json(api_nodes)

        # Return unknow if we can't find data
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find nodes data in the response.'
            return

        all_nodes_names = ''
        for item in parsed_json["items"]:
            all_nodes_names += '%s ' % item["metadata"]["name"]

            # print item["metadata"]["labels"]["region"]
            # print item["status"]["addresses"][0]["address"]
            # print item["status"]["conditions"][0]["type"]
            # print item["status"]["conditions"][0]["status"]
            # print item["status"]["conditions"][0]["reason"]

            # if status not ready
            if label_offline in item["metadata"]["labels"].keys():
                self.os_STATE = 1  # just warning
                self.os_OUTPUT_MESSAGE += "%s/%s: [Label: %s] " % (item["metadata"]["name"],
                                                                   item["status"]["addresses"][0]["address"],
                                                                   label_offline)

        if self.os_STATE == 0:
            self.os_OUTPUT_MESSAGE += '%s[schedulable]' % all_nodes_names

    def get_project_labels(self, required_labels):

        api_namespaces = '%s/namespaces' % self.base_api
        parsed_json = self.get_json(api_namespaces)

        # Return unknown if we can't find data
        if 'items' not in parsed_json:
            self.os_STATE = STATE_UNKNOWN
            self.os_OUTPUT_MESSAGE = ' Unable to find projects data in the response.'
            return

        all_project_names = []
        all_project_names_nok = []
        for project in parsed_json["items"]:
            all_project_names.append(project["metadata"]["name"])
            if 'labels' not in project["metadata"]:
                all_project_names_nok.append(project["metadata"]["name"])
                self.os_STATE = STATE_CRITICAL
            else:
                  for required_label in required_labels:
                      if not required_label in project["metadata"]["labels"].keys():
                          all_project_names_nok.append(project["metadata"]["name"])
                          self.os_STATE = STATE_CRITICAL
                          break

        if self.os_STATE == 0:
            self.os_OUTPUT_MESSAGE += " Project(s) '%s' labeled with '%s'." % ( ', '.join(all_project_names), ', '.join(required_labels))

        if self.os_STATE != 0:
            self.os_OUTPUT_MESSAGE += " Project(s) '%s' not labeled with '%s'." % ( ', '.join(all_project_names_nok), ', '.join(required_labels))

if __name__ == "__main__":

    # https://docs.openshift.com/enterprise/3.0/rest_api/openshift_v1.html

    if ARGS.version:
        print "version: %s" % (VERSION)
        sys.exit(0)

    if not ARGS.token and not ARGS.tokenfile and not (ARGS.username and ARGS.password):
        PARSER.print_help()
        sys.exit(STATE_UNKNOWN)

    myos = Openshift(host=ARGS.host,
                     port=ARGS.port,
                     username=ARGS.username,
                     password=ARGS.password,
                     token=ARGS.token,
                     tokenfile=ARGS.tokenfile,
                     proto=ARGS.protocol,
                     base_api=ARGS.base_api,
                     warn_avai_pv=ARGS.warn_avai_pv,
                     crit_avai_pv=ARGS.crit_avai_pv,
                     warn_relea_pv=ARGS.warn_relea_pv,
                     crit_relea_pv=ARGS.crit_relea_pv,
                     exclude_pods=ARGS.exclude_pods,
                     exclude_pvs=ARGS.exclude_pvs
                     )

    if ARGS.check_nodes:
        myos.get_nodes()

    if ARGS.check_pods:
        myos.get_pods('',ARGS.exclude_pods)

    if ARGS.check_pvs:
        myos.get_pvs(ARGS.warn_avai_pv,ARGS.crit_avai_pv,ARGS.warn_relea_pv,ARGS.crit_relea_pv,ARGS.exclude_pvs)

    if ARGS.check_labels:
        myos.get_labels(ARGS.label_offline)

    if ARGS.check_project_labels:
        myos.get_project_labels(ARGS.required_project_labels)

    if ARGS.check_scheduling:
        myos.get_scheduling()

    try:
        STATE = myos.os_STATE        
        OUTPUT_MESSAGE = "%s | %s" % (myos.os_OUTPUT_MESSAGE, myos.os_OUTPUT_MESSAGE_PERFDATA)
        print "%s:%s" % (STATE_TEXT[STATE], OUTPUT_MESSAGE)
        sys.exit(STATE)
    except ValueError:
        print "Oops!  cant return STATE"

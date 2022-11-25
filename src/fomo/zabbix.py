import os
import os.path
import sys
import json
import re
import time
import pytomlpp
import textwrap
from tabulate import tabulate
from datetime import date
from pprint import pprint
from pyzabbix import ZabbixAPI

#--- Custom Exceptions/classes
class UserNotFound(Exception):
    pass

class UserGroupNotFound(Exception):
    pass

class HostNotFound(Exception):
    pass

class HostGroupNotFound(Exception):
    pass

class TemplateNotFound(Exception):
    pass

class TriggerNotFound(Exception):
    pass

class ItemNotFound(Exception):
    pass

class MaintProfileNotFound(Exception):
    pass

priority_map = {
 "0":"Not Classified",
 "1":"INFO",
 "2":"WARN",
 "3":"MINOR",
 "4":"MAJOR",
 "5":"CRIT"
}

#--- Helper function for loading configuration options
def load_zabbix_config(config_option):
    fomo_toml_path=os.path.expanduser("~") + "/.fomo.toml"
    if os.path.exists(fomo_toml_path):
        try:
            return pytomlpp.loads(open(fomo_toml_path,"r").read()).get('zabbix',{}).get(config_option, "")
        except Exception as e:
            print(f"Error loading option {config_option} from {fomo_toml_path}:")
            raise
            #print(e)

#---
#--- Session class used to perform work against a Zabbix environment
#---
class Session:
  def __init__(self, zabbix_url="", api_key=""):
    """
    This method will initiate a session in the specified Zabbix environment with specified API key.
    Configuration will be loaded from fomo.toml if none explicitly specified
    """
    zabbix_url_source="specified"
    if zabbix_url == "":
        zabbix_url = load_zabbix_config("url")
        zabbix_url_source=".fomo.toml"
    api_key_source="specified"
    if api_key == "":
        api_key = load_zabbix_config("api_key")
        api_key_source=".fomo.toml"
    self._zapi = ZabbixAPI(zabbix_url)
    self._zapi.login(api_token=api_key)
    try:
        self._zapi.token.get()
    except Exception as e:
        print(e)
        print("Please verify authentication params used:")
        print(f"URL:\"{zabbix_url}\", Source:{api_key_source}")
        print(f"API_KEY:\"{api_key}\", Source:{zabbix_url_source}")

  def get_host(self,host_name, get_triggers=False):
    """
    This function will find a single host matching specified name (host field of zabbix host object).
    """
    if get_triggers:
        my_host = self._zapi.host.get(filter={"host": host_name}, output="extend", selectTags="extend", selectTriggers="triggerid")
    else:
        my_host = self._zapi.host.get(filter={"host": host_name}, output="extend", selectTags="extend")
    if not my_host:
        raise HostNotFound(f"Host {host_name} not found")
    return my_host[0]

  def get_all_hosts(self):
    """ 
    Retrieves all Hosts defined in Zabbix, output extended
    """
    return self._zapi.host.get(output="extend", selectTags="extend")

  def get_unmonitored_hosts(self):
    """ This will retrieve hosts that are not being monitored, either due to Maintenance or Disablement """
    my_unmonitored_hosts=[]
    my_unmonitored_hosts = self.get_hosts_in_maintenance()
    my_unmonitored_hosts = my_unmonitored_hosts + self.get_hosts_disabled()
    return my_unmonitored_hosts

  def get_hosts_in_maintenance(self):
    """ This will retrieve hosts that are actively in Maintenance mode """
    return self._zapi.host.get(filter={"maintenance_status":1}, output="extend", selectTags="extend")

  def get_hosts_disabled(self):
    """ This will retrieve hosts that are actively in Maintenance mode """
    return self._zapi.host.get(filter={"status":1}, output="extend", selectTags="extend")

  def get_templates(self, search_method, search_values):
    """ Returns specified Template matching search_method + search_values """
    valid_methods=['name','template_ids','trigger_ids']
    if search_method not in valid_methods:
        raise ValueError(f"Error search_method \"{search_method}\" invalid. Valid options: {str(valid_methods)}")
    if search_method == "name":
        my_templates = self._zapi.template.get(filter={"host": search_values}, output="extend", selectDiscoveries="extend", selectTriggers="triggerid", selectTags="extend")
    if search_method == "template_ids":
        my_templates = self._zapi.template.get(output="extend", templateids=search_values, selectDiscoveries="extend", selectTriggers="triggerid", selectTags="extend")
    elif search_method == "trigger_ids":
        my_templates = self._zapi.template.get(output="extend", triggerids=search_values, selectDiscoveries="extend", selectTriggers="triggerid", selectTags="extend")
    if not my_templates:
        raise TemplateNotFound(f"Template not found with given search criteria \"{search_method}={search_values}\"")
    return my_templates

  def get_all_templates(self):
    """ 
    Retrieves all Hosts defined in Zabbix, output extended
    """
    return self._zapi.template.get(output="extend", selectTags="extend", selectTriggers="extend")    
     
  def get_triggers(self, trigger_ids):
    """ Retrieve specified triggers based on filters """
    my_triggers = self._zapi.trigger.get(output="extend", selectTags="extend", selectHosts="extend", selectTriggerDiscovery="extend", expandExpression=True, expandDescription=True, expandComment=True, sortfield="priority", triggerids=trigger_ids)
    if not my_triggers:
        raise TriggerNotFound(f"No triggers found with supplied trigger_ids : {str(trigger_ids)}")
    return my_triggers

  def get_triggers_templated(self, trigger_ids):
    """ Retrieve specified triggers based on filters """
    my_triggers = self._zapi.trigger.get(triggerids=trigger_ids, templated=True, output="extend", selectTags="extend", selectHosts="extend", selectTriggerDiscovery="extend", expandExpression=True, expandDescription=True, expandComment=True, sortfield="priority")
    if not my_triggers:
        raise TriggerNotFound(f"No triggers found with supplied trigger_ids : {str(trigger_ids)}")
    return my_triggers

  def get_triggers_discovered(self, trigger_ids):
    """ Retrieve specified triggers based on filters """
    my_triggers = self._zapi.trigger.get(triggerids=trigger_ids, output="extend", selectTags="extend", selectHosts="extend", selectTriggerDiscovery="extend", expandExpression=True, expandDescription=True, expandComment=True, sortfield="priority")
    if not my_triggers:
        raise TriggerNotFound(f"No triggers found with supplied trigger_ids : {str(trigger_ids)}")
    return my_triggers

  def get_triggerprototype(self,triggerprototype_ids):
    """ Gets a trigger discovery by ID. """
    return self._zapi.triggerprototype.get(output="extend", selectTags="extend", expandExpression=True, triggerids=triggerprototype_ids)  

  def get_host_triggers(self, host_name, exclude_template_triggers=False, exclude_discovered_triggers=False):
    """
    Get all the Triggers associated to a Host specified by name
    """
    my_host = self.get_host(host_name,get_triggers=True)
    my_trigger_ids = [t.get('triggerid') for t in my_host['triggers']]
    my_triggers = []
    if not exclude_template_triggers and not exclude_discovered_triggers:
      my_triggers = self.get_triggers(trigger_ids=my_trigger_ids)  
    else:
      if exclude_template_triggers and exclude_discovered_triggers:
        # This area should get Triggers exclusive to this Host
        my_triggers = self.get_triggers(trigger_ids=my_trigger_ids)
    return my_triggers

  def get_template_triggers(self, template_name):
    """
    Get all the Triggers associated to a specified Template, by name
    """

  def get_items(self, item_ids: list):
    """ Returns the specified items - item IDs must be provided """
    my_items=[]
    my_items = self._zapi.item.get(output="extend", itemids=item_ids)

  def get_maint_profile(self, search_method, search_values):
    """ Gets a maintenance profile by specified name """
    valid_methods=['name','maintenance_ids']
    if search_method not in valid_methods:
        raise ValueError(f"Error search_method \"{search_method}\" invalid. Valid options: {str(valid_methods)}")
    if search_method == "name":
        my_maint_profiles = self._zapi.maintenance.get(filter={"name": search_values}, output="extend", selectHosts=["hostid","host"], selectGroups="extend", selectTags="extend", selectTimeperiods="extend")
    elif search_method == "maintenance_ids":
        my_maint_profiles = self._zapi.maintenance.get(maintenanceids=search_values, output="extend", selectHosts=["hostid","host"], selectGroups="extend", selectTags="extend", selectTimeperiods="extend")
    if not my_maint_profiles:
        raise MaintProfileNotFound(f"Maintenance Profiles \"{str(search_values)}\" not found")
    return my_maint_profiles

  def get_all_maint_profiles(self,only_active=False):
    """ Gets all maintenance profiles """
    my_maint_profiles = self._zapi.maintenance.get(output="extend", selectHosts=["hostid","host"], selectGroups="extend", selectTags="extend", selectTimeperiods="extend")
    return my_maint_profiles

  #---
  #--- TAGGING FUNCTIONS
  #---
  def get_host_trigger_cmdb_tags(self):
    """ 
    This method will retrieve all trigger definitions that need to be tagged. This means they are currently, actively applied to Host(s).
    """
    all_hosts = self.get_all_hosts()
    report_data=[]
    for h in all_hosts:
      my_report_item={"host":h['host']}
      
      

  def add_tag_triggerprototype(self, triggerprototype_id, tag_key, tag_value):
    """ Tag the specified trigger prototype(s) with the specified tag key:value """
    my_trigger = (self.get_triggers(triggerprototype_ids=triggerprototype_id))[0]
    my_tags=my_trigger['tags']
    my_tags.append({'tag':tag_key, 'value':tag_value})
    self._zapi.trigger.update(triggerid=my_trigger['triggerid'], tags=my_tags)

  def add_tag_trigger(self, trigger_id, tag_key, tag_value):
    """ Tag the specified trigger(s) with the specified tag key:value """
    my_trigger = (self.get_triggers(trigger_ids=trigger_id))[0]
    my_tags=my_trigger['tags']
    my_tags.append({'tag':tag_key, 'value':tag_value})
    self._zapi.trigger.update(triggerid=my_trigger['triggerid'], tags=my_tags)

  def tag_trigger_for_cmdb(self, trigger_id, impacted_ci, affected_ci, overwrite=False):
    """ Does tagging specifically for purpose of CMDB integration, for fields "impacted_ci" and "affected_ci" """
    my_trigger = (self.get_triggers(trigger_ids=trigger_id))[0]
    my_tags=my_trigger['tags']
    replace_needed=False
    my_new_tags=[]
    for t in my_tags:
      if t['tag'] == "impacted_ci" or t['tag'] == "affected_ci":
        print(f"{t['tag']}={t['value']} already defined.")
        replace_needed=True
      else:
        my_new_tags.append(t)
    if not overwrite and replace_needed:
      raise Exception("Replace=False, and 1 or more CMDB tags already present. Stopping.")
    my_new_tags.append({'tag':"impacted_ci", 'value':impacted_ci}) #add impacted_ci
    my_new_tags.append({'tag':"affected_ci", 'value':affected_ci}) #add affected_ci
    self._zapi.trigger.update(triggerid=my_trigger['triggerid'], tags=my_new_tags)

  def tag_triggerprototype_for_cmdb(self, trigger_id, impacted_ci, affected_ci, overwrite=False):
    """ Does tagging specifically for purpose of CMDB integration, for fields "impacted_ci" and "affected_ci" """
    my_trigger = (self.get_triggerprototype(triggerprototype_ids=trigger_id))[0]
    my_tags=my_trigger['tags']
    replace_needed=False
    my_new_tags=[]
    for t in my_tags:
      if t['tag'] == "impacted_ci" or t['tag'] == "affected_ci":
        print(f"{t['tag']}={t['value']} already defined.")
        replace_needed=True
      else:
        my_new_tags.append(t)
    if not overwrite and replace_needed:
      raise Exception("Replace=False, and 1 or more CMDB tags already present. Stopping.")
    my_new_tags.append({'tag':"impacted_ci", 'value':impacted_ci}) #add impacted_ci
    my_new_tags.append({'tag':"affected_ci", 'value':affected_ci}) #add affected_ci
    self._zapi.triggerprototype.update(triggerid=my_trigger['triggerid'], tags=my_new_tags)

  #---
  #--- PRINTING FUNCTIONS
  #---
  def print_triggers(self,my_triggers,csv=False):
    """ Does a pretty, formatted print against a list of trigger objects """
    preferredWidth = 200
    for t in my_triggers:
      if not t['recovery_expression']:
        t_recovery = "Same as expression"
      else:
        t_recovery = t['recovery_expression']
      my_comments=t['comments'].replace("\r\n","")
      #my_template=self.get_templates("trigger_ids",t['triggerid'])
      if csv:
        my_tags=""
        for tag in t['tags']:
          my_tags = my_tags + f"{tag['tag']}:{tag['value']},"
          my_tags.replace(" ",",")
        my_tags
        #--- Print csv format (delimted by ::)
        print(f"{t['triggerid']}::{t['description']}::{t['templateid']}::{str(t['tags'])}::{t['expression']}::{t_recovery}::{my_comments}")
      else:    
        print()  
        print(f"TriggerId : {t['triggerid']}")
        print(f"  Overview")
        print(f"  - Name        : {t['description']}")
        print(f"  - TemplateId  : {t['templateid']}")
        prefix="  - Tags        : "
        wrapper = textwrap.TextWrapper(initial_indent=prefix, width=preferredWidth, subsequent_indent=' '*len(prefix))
        message = ""
        for tag in t['tags']:
            message = message + f"{tag['tag']}:{tag['value']}\r\n"
        print(wrapper.fill(message))
        print(f"  Conditions")
        #print(f"  - Items      : ")
        prefix="  - Expression  : "
        wrapper = textwrap.TextWrapper(initial_indent=prefix, width=preferredWidth, subsequent_indent=' '*len(prefix))
        message = t['expression']
        print(wrapper.fill(message))
        prefix="  - Recovery    : "
        wrapper = textwrap.TextWrapper(initial_indent=prefix, width=preferredWidth, subsequent_indent=' '*len(prefix))
        message = t_recovery
        print(wrapper.fill(message))
        prefix="  - Description : "
        wrapper = textwrap.TextWrapper(initial_indent=prefix, width=preferredWidth, subsequent_indent=' '*len(prefix))
        message = my_comments
        print(wrapper.fill(message))
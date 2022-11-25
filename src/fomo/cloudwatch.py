#!/usr/bin/python

from asyncio import format_helpers
import boto3
import boto3.session
import botocore
import os
import sys
import json 
import re
import time
from tabulate import tabulate
from datetime import date
from pprint import pprint

#--- Custom Exceptions/classes
class AlarmNotFound(Exception):
    pass

class SnsNotFound(Exception):
    pass

class DashboardNotFound(Exception):
    pass

class LogGroupNotFound(Exception):
    pass

class MetricFilterNotFound(Exception):
    pass

#---
#--- Session class used to perform work against an AWS Account+Region environment
#---
class Session:
  def __init__(self, access_key="", secret_key="", session_token="", region_name="us-east-1"):
    """ 
    This method will initiate a session in the specified region. 
    Environmental Access Key and Secret will be used if none specified 
    """
    self._region=region_name
    # if no access key/secret/session specified, or one missing, try to create via environment
    if access_key=="" or secret_key=="" or session_token=="":
        self._session=boto3.session.Session(region_name=self._region)
    # if all 3 provided, try to create session with provided key(s)
    else:
        self._session=boto3.session.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, aws_session_token=session_token, region_name=self._region)
    # create clients to use for internal method calls
    self._cloudwatch=self._session.client('cloudwatch', region_name=self._region)
    self._sns=self._session.client('sns', region_name=self._region)
    self._cwlogs=self._session.client('logs', region_name=self._region)   
  
  #---
  #--- ALARMS
  #---
  def get_alarm(self,alarm_name):
      """ 
      This function will find a single alarm matching specified name.
      """
      my_alarm=self._cloudwatch.describe_alarms(AlarmNames=[alarm_name],AlarmTypes=['MetricAlarm','CompositeAlarm'])
      if not my_alarm['MetricAlarms'] and not my_alarm['CompositeAlarms']:
          raise AlarmNotFound("Alarm '%s' not found" % alarm_name)
      if my_alarm['MetricAlarms']:
          return(my_alarm['MetricAlarms'][0])
      if my_alarm['CompositeAlarms']:
          return(my_alarm['CompositeAlarms'][0])
  
  def get_alarm_type(self,my_alarm):
      """ 
      Simple method that returns alarms type as MetricAlarm or CompositeAlarm, to help keep the end-user abstracted.
      """
      if "ComparisonOperator" in my_alarm:
          return("MetricAlarm")
      elif "AlarmRule" in my_alarm:
          return("CompositeAlarm")
      else:
          raise Exception("Unable to determine alarm type for '%s' - bad object." % my_alarm)    
  
  def get_all_alarms(self):
      """ 
      This function will gather all available MetricAlarms an CompositeAlarms
      """
      all_alarms=self._cloudwatch.get_paginator('describe_alarms').paginate(AlarmTypes=['MetricAlarm','CompositeAlarm']).build_full_result()
      return(all_alarms)
  
  def put_metric_alarm(self,my_alarm,overwrite=False):
      """ 
      This fomo function will create a metric alarm when passed a metric alarm object. It's intent is to abstract the user from how to craft the specific payload.
      This helps with quick "inline" modifications of alarms, as well, when using fomo functions on the command line.
      As a safety precaution, it will not overwrite alarms by default, so "overwrite=True" must be specified.
      """
      # unless specified otherwise, the following will prevent an alarm from being overwritten
      if not isinstance(overwrite, bool):
          raise TypeError("overwrite Must be boolean (True/False) : '%s' specified." % overwrite)
      if not overwrite:
          try:
              self.get_alarm(my_alarm['AlarmName'])
              raise Exception("overwrite is set to '%s', and an alarm was found with name '%s'. Stopping" % (overwrite, my_alarm['AlarmName']))
          except AlarmNotFound:
              pass
      # add the TreatMissingData value if it is missing
      if "TreatMissingData" not in my_alarm:
          my_alarm['TreatMissingData']="missing"
      if "DatapointsToAlarm" not in my_alarm:
          # Just use EvaluationPeriods : the default when DatapointsToAlarm is not specified.
          my_alarm['DatapointsToAlarm']=my_alarm['EvaluationPeriods']
      if "AlarmDescription" not in my_alarm:
          my_alarm['AlarmDescription']="No description"
      try:
          # this block is used for MetricAlarms based on a single metric
          if my_alarm['MetricName']:
              try:
                  # this block is used for MetricAlarms based on a single metric using a Standard statistic
                  if my_alarm['Statistic']:
                      self._cloudwatch.put_metric_alarm(
                          AlarmName=my_alarm['AlarmName'],
                          ActionsEnabled=my_alarm['ActionsEnabled'],
                          OKActions=my_alarm['OKActions'],
                          AlarmActions=my_alarm['AlarmActions'],
                          InsufficientDataActions=my_alarm['InsufficientDataActions'],
                          MetricName=my_alarm['MetricName'],
                          Namespace=my_alarm['Namespace'],
                          Statistic=my_alarm['Statistic'],
                          Dimensions=my_alarm['Dimensions'],
                          Period=my_alarm['Period'],
                          EvaluationPeriods=my_alarm['EvaluationPeriods'],
                          DatapointsToAlarm=my_alarm['DatapointsToAlarm'],
                          Threshold=my_alarm['Threshold'],
                          ComparisonOperator=my_alarm['ComparisonOperator'],
                          TreatMissingData=my_alarm['TreatMissingData'],
                          AlarmDescription=my_alarm['AlarmDescription']
                      )
                      return
              except(KeyError):
                  pass
              # this block is used for MetricAlarms based on a single metric using an Expandable, or Extended, statistic
              if my_alarm['ExtendedStatistic']:
                  self._cloudwatch.put_metric_alarm(
                      AlarmName=my_alarm['AlarmName'],
                      ActionsEnabled=my_alarm['ActionsEnabled'],
                      OKActions=my_alarm['OKActions'],
                      AlarmActions=my_alarm['AlarmActions'],
                      InsufficientDataActions=my_alarm['InsufficientDataActions'],
                      MetricName=my_alarm['MetricName'],
                      Namespace=my_alarm['Namespace'],
                      ExtendedStatistic=my_alarm['ExtendedStatistic'],
                      Dimensions=my_alarm['Dimensions'],
                      Period=my_alarm['Period'],
                      EvaluationPeriods=my_alarm['EvaluationPeriods'],
                      DatapointsToAlarm=my_alarm['DatapointsToAlarm'],
                      Threshold=my_alarm['Threshold'],
                      ComparisonOperator=my_alarm['ComparisonOperator'],
                      TreatMissingData=my_alarm['TreatMissingData'],
                      AlarmDescription=my_alarm['AlarmDescription']
                  )
                  return
      except(KeyError):
          pass
      # this block is used for MetricAlarms or Anomaly Detection alarms, containing the "Metrics" key:value 
      if my_alarm['Metrics']:
          # this block is used for MetricAlarms that are based on Anomaly detection and therefore have the ThresholdMetricId key
          if "ThresholdMetricId" in my_alarm:
              self._cloudwatch.put_metric_alarm(
                  AlarmName=my_alarm['AlarmName'],
                  ActionsEnabled=my_alarm['ActionsEnabled'],
                  OKActions=my_alarm['OKActions'],
                  AlarmActions=my_alarm['AlarmActions'],
                  InsufficientDataActions=my_alarm['InsufficientDataActions'],
                  Metrics=my_alarm['Metrics'],
                  EvaluationPeriods=my_alarm['EvaluationPeriods'],
                  DatapointsToAlarm=my_alarm['DatapointsToAlarm'],
                  ThresholdMetricId=my_alarm['ThresholdMetricId'],
                  ComparisonOperator=my_alarm['ComparisonOperator'],
                  TreatMissingData=my_alarm['TreatMissingData'],
                  AlarmDescription=my_alarm['AlarmDescription']
              )
              return
          else:
              # this block is used for MetricAlarms based on a "static" mathematical expression using multiple metrics
              self._cloudwatch.put_metric_alarm(
                  AlarmName=my_alarm['AlarmName'],
                  ActionsEnabled=my_alarm['ActionsEnabled'],
                  OKActions=my_alarm['OKActions'],
                  AlarmActions=my_alarm['AlarmActions'],
                  InsufficientDataActions=my_alarm['InsufficientDataActions'],
                  Metrics=my_alarm['Metrics'],
                  EvaluationPeriods=my_alarm['EvaluationPeriods'],
                  DatapointsToAlarm=my_alarm['DatapointsToAlarm'],
                  Threshold=my_alarm['Threshold'],
                  ComparisonOperator=my_alarm['ComparisonOperator'],
                  TreatMissingData=my_alarm['TreatMissingData'],
                  AlarmDescription=my_alarm['AlarmDescription']
              )
              return      
  
  def put_composite_alarm(self,my_alarm,overwrite=False):
      """ 
      This fomo function will create a composite alarm when passed a composite alarm object.
      It is meant to be reusable, and abstract the user from the logic needed to determine how to craft the PutCompositeAlarm payload.
      """
      if not isinstance(overwrite, bool):
          raise TypeError("overwrite Must be boolean (True/False) : '%s' specified." % overwrite)
      if not overwrite:
          try:
              self.get_alarm(my_alarm['AlarmName'])
              raise Exception("overwrite is set to '%s', and an alarm was found with name '%s'. Stopping" % (overwrite, my_alarm['AlarmName']))
          except AlarmNotFound:
              pass
      if "AlarmDescription" not in my_alarm:
          my_alarm['AlarmDescription']="No description"
      self._cloudwatch.put_composite_alarm(
          ActionsEnabled=my_alarm['ActionsEnabled'],
          AlarmActions=my_alarm['AlarmActions'],
          AlarmDescription=my_alarm['AlarmDescription'],
          AlarmName=my_alarm['AlarmName'],
          AlarmRule=my_alarm['AlarmRule'],
          InsufficientDataActions=my_alarm['InsufficientDataActions'],
          OKActions=my_alarm['OKActions']
      )
      return
  
  def rename_alarm(self, alarm_name, new_alarm_name, keep_old_alarm):
      """
      This function will rename an existing alarm. 
      To prevent the old alarm from being removed, specify "keep_old_alarm=True"
      To remove the old alarm from being removed, specify "keep_old_alarm=False"
      """
      if not isinstance(keep_old_alarm, bool):
          raise TypeError("keep_old_alarm Must be boolean (True/False) : '%s' specified." % keep_old_alarm)
      #if len(new_alarm_name == 0):
      #    raise Exception("new_alarm_name cannot be empty string.")
      my_alarm = self.get_alarm(alarm_name)
      # update the alarm name in code object
      my_alarm['AlarmName']=new_alarm_name
      alarm_type=self.get_alarm_type(my_alarm)
      # update the alarm name in cloudwatch
      if alarm_type == "MetricAlarm":
          self.put_metric_alarm(my_alarm)
      if alarm_type == "CompositeAlarm":
          self.put_composite_alarm(my_alarm)    
      # decide to keep or remove the old named alarm
      if not keep_old_alarm:
          self.delete_alarm(alarm_name,confirm=True)
  
  def get_alarms_from_list(self):
      """ This will create a List of alarms from a newline seperated list of alarm names, input directly into console """
      print("Please paste newline delimited list of Alarm Names.(Press Ctrl+D when done.)")
      alarm_names=sys.stdin.readlines()
      my_alarms=[]
      for n in alarm_names:
          my_alarms.append(self.get_alarm(n.strip('\n')))
      print("Successfully found all alarms.")
      return my_alarms
  
  def get_list_from_list(self, user_prompt):
      """ This will create a Pyton List from newline seperated list of strings, input directly into console. """
      print(user_prompt + "(Press Ctrl+D when done.)")
      input=sys.stdin.readlines()
      my_list=[]
      for l in input:
          my_list.append(l.strip('\n'))
      return my_list
  
  def rename_alarms_by_list(self):
      """ 
      This method will accept lists of alarm names before, and after, and perform the specified renames
      It is meant to be used interactively, and will prompt the user with details of the renames be run for confirmation
      """
      my_alarms=self.get_alarms_from_list()
      print("")
      my_alarm_new_names=self.get_list_from_list("Please specify list of New Alarm Names, in same order as Alarms were specified.")
      print("")
      i=0
      # Build table to prompt user for confirmation
      alarm_rename_list=[]
      for a in my_alarms:
          alarm_rename_list.append([a['AlarmName'],my_alarm_new_names[i]])
          i=i+1
      print("Alarm Names compared to New Alarm Names")    
      print(tabulate(alarm_rename_list))
      print("")
      response=input("Please confirm that you want to perform these renames (y/n)")
      if response.lower() == "y":
          for a in alarm_rename_list:
              print("Disabling alarm... ")
              self.disable_alarm(a[0])
              time.sleep(2)
              print("Renaming alarm...")
              print("FROM: " + a[0])
              print("TO  : " + a[1])
              self.rename_alarm(a[0],a[1],keep_old_alarm=False)
              print("")
      else:
          print("Response 'y' not specified. No renames performed.")
          return
      final_msg="""
      Renames completed successfully.
      The alarms have been left Disabled (ActionsEnabled=False)
      Re-enable the Alarms when their StateValue has evaluated to OK.
      """    
      print(final_msg)   
      i=0
      alarm_disabled_list=[]
      alarm_enabled_list=[]
      for a in my_alarms:
          if not a['ActionsEnabled']:
              alarm_disabled_list.append([a['AlarmName'],my_alarm_new_names[i]])
          else:
              alarm_enabled_list.append([a['AlarmName'],my_alarm_new_names[i]])
          i=i+1
      print("Alarms that were Disabled before renamed")    
      print(tabulate(alarm_disabled_list))
      print()
      print("Alarms that were Enabled before renamed")    
      print(tabulate(alarm_enabled_list))
  
  
  def delete_alarm(self, alarm_name, confirm=False):
      """ Simple method to delete alarm specified by alarm_name """
      if not isinstance(confirm, bool):
          raise TypeError("confirm Must be boolean (True/False) : '%s' specified." % confirm)
      if not confirm:
          raise Exception("Alarm '%s' not removed : If it exists, you must specify confirm=True to remove it." % alarm_name)    
      if confirm:     
          self.get_alarm(alarm_name)
          self._cloudwatch.delete_alarms(AlarmNames=[alarm_name])
  
  def copy_alarm(self, alarm_name, new_alarm_name):
      """
      This function will copy an existing alarm, using the "rename_alarm" method. 
      """
      self.rename_alarm(alarm_name, new_alarm_name, keep_old_alarm=True)
  
  def disable_alarm(self, alarm_name):
      """ 
      Disable an alarm's actions for maintenace or otherwise. 
      Since this function is only modifying "ActionsEnabled", overwrite is set to True
      """
      my_alarm=self.get_alarm(alarm_name)
      my_alarm['ActionsEnabled']=False
      alarm_type=self.get_alarm_type(my_alarm)
      if alarm_type == 'MetricAlarm':
          self.put_metric_alarm(my_alarm,overwrite=True)
      if alarm_type == 'CompositeAlarm':
          self.put_composite_alarm(my_alarm,overwrite=True)
  
  def enable_alarm(self, alarm_name):
      """ 
      Will enable an alarm's actions 
      Since this function is only modifying "ActionsEnabled", overwrite is set to True
      """
      my_alarm=self.get_alarm(alarm_name)
      my_alarm['ActionsEnabled']=True
      alarm_type=self.get_alarm_type(my_alarm)
      if alarm_type == 'MetricAlarm':
          self.put_metric_alarm(my_alarm,overwrite=True)
      if alarm_type == 'CompositeAlarm':
          self.put_composite_alarm(my_alarm,overwrite=True)
  
  def replace_active_alarm_string(self,alarm_name, search_string, replace_string, make_alarm_update=False):
      """
      This method is meant to help replace metric/dimensions values via string replace.
      It will parse the config of given alarm and mass-replace any occurrence of "search_string" with "replace_string."
      By default, the Alarm payload is returned and the change is not made. To make the change, specify "make_alarm_update=True"
      Future Note: To change an alarm's name, use the "rename_alarm" function instead.
      Future Note: This implementation is done simply and prone to error. A future update would do this more intelligently.
      """
      if not isinstance(make_alarm_update, bool):
          raise TypeError("make_alarm_update Must be boolean (True/False) : '%s' specified." % make_alarm_update)
      my_alarm=self.get_alarm(alarm_name)
      replaced_alarm=json.loads(json.dumps(my_alarm,default=str).replace(search_string,replace_string))
      if make_alarm_update:
          self.put_metric_alarm(replaced_alarm,overwrite=True)
      else:
          #print("Alarm config returned, but not applied. Re-run command with \"make_alarm_update=True\" to make the change.")
          return replaced_alarm
  
  def modify_alarm_action(self, alarm_name, modify_action, action_type, sns_name):
      """ 
      Modify an Alarm action, to either add/remove an SNS topic to OKActions,AlarmActions,or InsufficientDataActions
        modify_action: add,remove
        action_type: AlarmActions,OKActions,InsufficientDataActions
        sns_name: Valid sns topic name. Can be discovered with get_all_sns()
      """
      valid_modify_actions=['add','remove']
      if modify_action not in valid_modify_actions:
          raise Exception("Error modify_action '%s' invalid. Valid options: '%s'" % (modify_action,str(valid_modify_actions)))       
      valid_action_types=['OKActions','AlarmActions','InsufficientDataActions']
      if action_type not in valid_action_types:
          raise Exception("Error action_type '%s' invalid. Valid options: '%s'" % (action_type,str(valid_action_types)))       
      my_alarm=self.get_alarm(alarm_name)
      my_sns=self.get_sns(sns_name)
      if modify_action == 'add':
          if my_sns not in my_alarm[action_type]:
              my_alarm[action_type].append(my_sns)
              self.put_metric_alarm(my_alarm,overwrite=True)
      if modify_action == 'remove':
          if my_sns in my_alarm[action_type]:
              my_alarm[action_type].remove(my_sns)
              self.put_metric_alarm(my_alarm,overwrite=True)
  
  def modify_alarm_treatmissingdata(self, alarm_name, treat_missing_data):
      """ 
      Will update how an alarm handles missing data.
        treat_missing_data: missing,breaching,notBreaching,ignore 
      """
      valid_missing_options=['missing','breaching','notBreaching','ignore']
      if treat_missing_data not in valid_missing_options:
          raise Exception("Option treat_missing_data '%s' invalid. Valid options: '%s'" % (treat_missing_data,str(valid_missing_options)))
      my_alarm=self.get_alarm(alarm_name)
      my_alarm['TreatMissingData']=treat_missing_data
      self.put_metric_alarm(my_alarm,overwrite=True)
  
  def modify_alarm_description(self, alarm_name, impacted_ci, affected_ci, details="", overwrite=False):
      """ This method will perform a standardized update of Alarm descriptions """
      my_alarm=self.get_alarm(alarm_name)
      my_description=""
      my_description_lines=my_alarm["AlarmDescription"].split("\n")
      # find Impacte_CI first - if not found, create it
      current_impacted_ci=""
      for l in my_description_lines:
          if "Impacted_CI:" in l:
              current_impacted_ci=(l.split(":")[-1]).strip()
      if current_impacted_ci != "" and impacted_ci != current_impacted_ci:
          if overwrite:
              print("Impacted_CI will be changed from \"" + current_impacted_ci + "\" to \"" + impacted_ci + "\"")
          else:
              raise Exception("Current Impacted_CI \"" + current_impacted_ci + "\" does not match \"" + impacted_ci + "\" and overwrite=False. Specify overwrite=True to continue.")       
      my_description+="Impacted_CI: " + impacted_ci
      my_description+="\n"
      # find Affected_CI next - if not found, create it
      current_affected_ci=""
      for l in my_description_lines:
          if "Affected_CI:" in l:
              current_affected_ci=(l.split(":")[-1]).strip()
      if current_affected_ci != "" and affected_ci != current_affected_ci:
          if overwrite:
              print("Affected_CI will be changed from \"" + current_affected_ci + "\" to \"" + affected_ci + "\"")
          else:
              raise Exception("Current Affected_CI \"" + current_affected_ci + "\" does not match \"" + affected_ci + "\" and overwrite=False. Specify overwrite=True to continue.")       
      my_description+="Affected_CI " + affected_ci
      my_description+="\n"
      # find Details next - if not found, create it. 
      current_details=""
      for l in my_description_lines:
          if "Details:" in l:
              #current_details=' '.join(l.split(":")[1::])
              current_details=l.split("Details: ")[-1].rstrip()
      if details == "":
          # No new details specified - retain the old details (or lack therof)
          details = current_details.rstrip()
      else:
          # If no new details was specified, keep the same details
          if details != current_details.restrip():
              if overwrite:
                  print("Details will be changed from \"" + current_details + "\" to \"" + details + "\"")
              else:
                  raise Exception("Current Details \"" + current_details + "\" does not match \"" + details + "\" and overwrite=False. Specify overwrite=True to continue.")      
      # - Append unlabelled lines to the end of Details - remove newline.
      for l in my_description_lines:
          if "Details:" not in l and "Impacted_CI:" not in l and "Affected_CI:" not in l:
              # Found untagged lines. Append them to details.
              if l != "":
                  details+=" "
                  details+=l.rstrip()
      my_description += "Details: " + details
      my_alarm["AlarmDescription"] = my_description
      self.put_metric_alarm(my_alarm,overwrite=True)
  
  """
  def modify_alarm_tag(alarm_name,modify_action,tag_key,tag_value,overwrite=False):
      # Adds or Removes designated tags to a CloudWatch alarm. tag_value not required to untag a resource 
      valid_action_options=['add','remove']
      # test tag key
      # test tag value
      my_alarm=get_alarm(alarm_name)
  
      cloudwatch.tag_resource(
                  ResourceARN=alarm_arn,
                  Tags=[
                   {
                      'Key': tag_key,
                      'Value' : tag_value
                   }
                  ]
              )
  """
  
  def backup_alarm(self, alarm_name, filepath,overwrite=False):
      """ 
      Backs up a single alarms configuration to a file, referenced by name.
      """
      if os.path.exists(filepath) and overwrite == False:
          raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
      my_alarm_str=json.dumps(self.get_alarm(alarm_name),default=str)
      f=open(filepath,"w")
      f.write(my_alarm_str)
      f.close()

  def backup_all_alarms(self, filepath, overwrite=False):
      """ 
      Backs up all avaialble alarms configurations to a file.
      """
      if os.path.exists(filepath) and overwrite == False:
          raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
      my_alarms_str=json.dumps(self.get_all_alarms(),default=str)
      f=open(filepath,"w")
      f.write(my_alarms_str)
      f.close()
  
  def restore_alarm(self, filepath, alarm_name, confirm=False):
      """ 
      This command will restore an alarm's configuration from a file.
      """
      my_alarms=self.load_alarms(filepath)
      alarm_found=False
      for alarm in my_alarms['MetricAlarms']:
          if alarm['AlarmName'] == alarm_name:
              print("Alarm found : " + alarm['AlarmArn'])
              alarm_found=True
              if confirm == False:
                  response=input("Confirm you want to restore this alarm from file? (y/n)")
                  if response.lower() == "y":
                      confirm=True
                  else:
                      print("Response 'y' not specified. Alarm not restored.")
              if confirm == True:
                  self.put_metric_alarm(alarm,overwrite=True)
                  print("Successfully restored alarm '%s'!" % alarm_name)
      if alarm_found==False:
          print("Alarm '%s' was not found." % alarm_name)
  
  #---
  #--- SNS
  #---
  def get_all_sns(self):
      """ 
      Gets all SNS topics
      """
      all_topics=self._sns.get_paginator('list_topics').paginate().build_full_result()
      return(all_topics['Topics'])
  
  def get_sns(self, sns_name):
      """ 
      Get SNS topic name of a specific name or ARN. By default, search is done by Name
      """
      my_sns = None
      #valid_search_methods=['Name','ARN']
      #if search_method not in valid_search_methods:
          #raise Exception("Error: search_method '%s' specified was invalid, valid options are '%s'" % (search_method,str(valid_search_methods)))
      for s in self.get_all_sns():
          if s['TopicArn'].split(":")[-1] == sns_name:
              my_sns=s['TopicArn']
      if my_sns == None:
          raise SnsNotFound("SNS Topic '%s' not found" % sns_name)
      return my_sns
  
  def create_sns(self, sns_name):
      """ Creates a new SNS topic of the given Name """
      self._sns.create_topic(Name=sns_name)
  
  def add_sns_subscription(self, sns_name, subscription_type, subscription_target):
      """ 
      Adds a subscription to specified SNS Topic.
        sns_name: String
        subscription_type: Email,HTTPS 
        subcription_target: Email address / URL
      """
      valid_sub_types=['email','https']
      if subscription_type not in valid_sub_types:
          raise Exception("Error subscription_type '%s' invalid. Valid options: '%s'" % (subscription_type,str(valid_sub_types)))     
      my_topic=self.get_sns(sns_name)  
      self._sns.subscribe(TopicArn=my_topic,Protocol=subscription_type,Endpoint=subscription_target)
  
  def delete_sns(self, sns_name):
      """ Deletes a sns topic, specified by name """
      my_topic=get_sns(sns_name)
      self._sns.delete_topic(TopicArn=my_topic)
  
  def get_sns_subscriptions(self, sns_name):
      """
      Obtains and returns list of SNS subscriptions related to a given SNS topic.
      """
      my_sns=self.get_sns(sns_name)
      my_sns_subscriptions = sns.list_subscriptions_by_topic(TopicArn=my_sns)
      return my_sns_subscriptions
 
  #---
  #--- DASHBOARDS
  #---
  def get_dashboard(self, dashboard_name):
      """ Get a specific dashboard from cloudwatch by exact name"""
      try:
          dashboard=self._cloudwatch.get_dashboard(DashboardName=dashboard_name)
      except botocore.exceptions.ClientError as error:
          raise DashboardNotFound("Dashboard '%s' not found" % dashboard_name)
      return dashboard
  
  def get_all_dashboards(self):
      """ Get all dashboards from cloudwatch """
      db_list=self._cloudwatch.list_dashboards()
      my_dashboards=[]
      for db in db_list['DashboardEntries']:
          dbname=db['DashboardName']
          my_dashboards.append(self._cloudwatch.get_dashboard(DashboardName=dbname))
      return my_dashboards
  
  def backup_dashboard(self, dashboard_name, filepath, overwrite=False):
      """ 
      Backs up dashboard specified by name to the specified file.
      """
      my_db = self.get_dashboard(dashboard_name)
      if os.path.exists(filepath) and overwrite == False:
          raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
      my_dashboards_str=json.dumps(my_db,default=str)
      f=open(filepath,"w")
      f.write(my_dashboards_str)
      f.close()

  def backup_all_dashboards(self, filepath, overwrite=False):
      """ 
      Backs up all available dashboard configurations to a file.
      """
      if os.path.exists(filepath) and overwrite == False:
          raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
      my_dashboards_str=json.dumps(self.get_all_dashboards(),default=str)
      f=open(filepath,"w")
      f.write(my_dashboards_str)
      f.close()
  
  def restore_dashboard(self, filepath, dashboard_name, confirm=False):
      """ 
      This command will restore an alarm's configuration from a file.
      """
      my_dashboards=self.load_dashboards(filepath)
      dashboard_found=False
      for dashboard in my_dashboards:
          if dashboard['DashboardName'] == dashboard_name:
              print("Dashboard found : " + dashboard['DashboardArn'])
              dashboard_found=True
              if confirm == False:
                  response=input("Confirm you want to restore this Dashboard from file? (y/n)")
                  if response.lower() == "y":
                      confirm=True
                  else:
                      print("Response 'y' not specified. Dashboard not restored.")
              if confirm == True:
                  self.put_dashboard(dashboard,overwrite=True)
                  print("Successfully restored Dashboard '%s'!" % dashboard_name)
      if dashboard_found==False:
          print("Dashboard '%s' was not found." % dashboard_name)
  
  def put_dashboard(self, my_dashboard, overwrite=False):
      """ Post a dashboard object back to cloudwatch"""
      if not overwrite:
          try:
              self.get_dashboard(my_dashboard['DashboardName'])
              raise Exception("overwrite is set to '%s', and a dashboard was found with name '%s'. Stopping" % (overwrite, my_dashboard['DashboardName']))
          except DashboardNotFound:
              pass
      self._cloudwatch.put_dashboard(
          DashboardName=my_dashboard['DashboardName'],
          DashboardBody=my_dashboard['DashboardBody']
      )
  
  def rename_dashboard(self, dashboard_name, new_dashboard_name, keep_old_dashboard):
      """ 
      Updates the name of an existing dashboard.
      Specify keep_old_alarm to remove the previous version of the dashboard.
      """
      if not isinstance(keep_old_dashboard, bool):
          raise TypeError("keep_old_dashboard Must be boolean (True/False) : '%s' specified." % keep_old_dashboard)
      my_dashboard=self.get_dashboard(dashboard_name)
      if len(new_dashboard_name) == 0:
          raise Exception("new_dashboard_name cannot be empty string.")
      my_dashboard['DashboardName']=new_dashboard_name
      self.put_dashboard(my_dashboard)
      if keep_old_dashboard == False:
          self.delete_dashboard(dashboard_name,confirm=True)
  
  def delete_dashboard(self, dashboard_name, confirm=False):
      """ Will delete the specified dashboard, Must confirm=True """
      if not isinstance(confirm, bool):
          raise TypeError("confirm Must be boolean (True/False) : '%s' specified." % confirm)
      if not confirm:
          raise Exception("Dashboard '%s' not removed : If it exists, you must specify confirm=True to remove it." % dashboard_name)    
      if confirm:     
          self.get_dashboard(dashboard_name)
          self._cloudwatch.delete_dashboards(DashboardNames=[dashboard_name])
  
  def replace_active_dashboard_body_string(self, dashboard_name, search_string, replace_string, make_dashboard_update=False):
      """
      Search the contents of a Dashboard Body, and replaces "search_string" with "replace_string"
      """
      if not isinstance(make_dashboard_update, bool):
          raise TypeError("make_dashboard_update Must be boolean (True/False) : '%s' specified." % make_dashboard_update)
      my_dashboard=self.get_dashboard(dashboard_name)
      replaced_dashboard=json.loads(json.dumps(my_dashboard,default=str).replace(search_string,replace_string))
      if make_dashboard_update:
          self.put_dashboard(replaced_dashboard,overwrite=True)
      else:
          return replaced_dashboard
  
  #---
  #--- CLOUDWATCH LOG GROUPS
  #---
  def get_all_log_groups(self):
      """ Returns all Log Groups """
      all_log_groups=self._cwlogs.get_paginator('describe_log_groups').paginate().build_full_result()['logGroups']
      return(all_log_groups)
  
  def get_log_group(self, log_group_name):
      """ Returns a specified Log Group. Throws LogGroupNotFound error if not found """
      log_groups=self.get_all_log_groups()
      for lg in log_groups:
          if lg['logGroupName'] == log_group_name:
              return lg
      # If you hit this, the log group was not found. Throw error.
      raise LogGroupNotFound("Log Group '%s' not found" % log_group_name)
  
  #---
  #--- CLOUDWATCH LOG GROUPS METRIC FILTERS
  #---
  def get_all_metric_filters(self):
      """ Returns all Metric Filters associated to all Log Groups """
      all_metric_filters=self._cwlogs.get_paginator('describe_metric_filters').paginate().build_full_result()['metricFilters']
      return(all_metric_filters)
  
  def get_metric_filter(self, metric_filter_name, log_group_name):
      """ Returns metric filter of the specified name and log group""" 
      self.get_log_group(log_group_name)
      mfs=self.get_all_metric_filters()
      for mf in mfs:
          if mf['filterName'] == metric_filter_name and mf['logGroupName'] == log_group_name:
              return mf
      # If you hit this, the Metric Filter was not found. Throw error    
      raise MetricFilterNotFound("Metric Filter '%s' not found in log group '%s'" % (metric_filter_name,log_group_name))
  
  def put_metric_filter(self, my_filter,overwrite=False):
      """ Creates metric filter with defined parameters """
      if not overwrite:
          try:
              self.get_metric_filter(my_filter['filterName'],my_filter['logGroupName'])
              raise Exception("overwrite is set to '%s', and a metric filter was found with name '%s' in log group '%s'. Stopping" % (overwrite, my_filter['filterName'],my_filter['logGroupName']))
          except MetricFilterNotFound:
              pass
      self._cwlogs.put_metric_filter(
          logGroupName=my_filter['logGroupName'],
          filterName=my_filter['filterName'],
          filterPattern=my_filter['filterPattern'],
          metricTransformations=my_filter['metricTransformations']
      )
  
  def delete_metric_filter(self, metric_filter_name, log_group_name, confirm=False):
      """ Deletes specific metric filter """
      if not confirm:
          raise Exception("Metric filter '%s' in log group '%s' not removed : If it exists, you must specify confirm=True to remove it." % (metric_filter_name,log_group_name)    )
      if confirm:     
          self.get_metric_filter(metric_filter_name,log_group_name)
          self._cwlogs.delete_metric_filter(filterName=metric_filter_name,logGroupName=log_group_name)
  
  def backup_all_metric_filters(self, filepath, overwrite=False):
      """ 
      Backs up all available metric filters to a file.
      """
      if os.path.exists(filepath) and overwrite == False:
          raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
      my_metric_filter_str=json.dumps(self.get_all_metric_filters(),default=str)
      f=open(filepath,"w")
      f.write(my_metric_filter_str)
      f.close()
  
  def restore_metric_filter(self, filepath, metric_filter_name, confirm=False):
      """ 
      This command will restore a metric filter's configuration from a file.
      """
      my_metric_filters=self.load_metric_filters(filepath)
      metric_filter_found=False
      for mf in my_metric_filters:
          if mf['filterName'] == metric_filter_name:
              print("Metric Filter found : " + mf['filterName'])
              metric_filter_found=True
              if confirm == False:
                  response=input("Confirm you want to restore this metric filter from file? (y/n)")
                  if response.lower() == "y":
                      confirm=True
                  else:
                      print("Response 'y' not specified. Metric filter not restored.")
              if confirm == True:
                  self.put_metric_filter(mf,overwrite=True)
                  print("Successfully restored metric filter '%s'!" % metric_filter_name)
      if metric_filter_found==False:
          print("Metric filter '%s' was not found." % metric_filter_name)

#---
#--- Helper Functions (Printers, Backupers, Loaders, Filterers)
#---
def replace_object_string(my_object, search_string, replace_string, make_alarm_update=False):
    """
    This method will accept any object, perform a replace of "search_string" with "replace_string", and return object
    """
    replaced_alarm=json.loads(json.dumps(my_object,default=str).replace(search_string,replace_string))
    return replaced_alarm
 
def filter_metric_alarms(alarms, search_string, match_invert="match", search_by="all", return_type="full_alarm"):
    """ 
    This method is used to perform filters on a list of alarms and return the result(s) of the filterering.
    Filtering options: search_by=['all','name','metrics'], match_invert=['match','invert'], return_type=['name','full_alarm']
    """
    try:
        if "MetricAlarms" in alarms.keys():
            my_alarms=alarms['MetricAlarms']
    except AttributeError:
        my_alarms=alarms
        pass
    valid_return_types=['name','full_alarm']
    if return_type not in valid_return_types:
        raise Exception("Error return_type '%s' invalid. Valid options: '%s'" % (return_type,str(valid_return_types)))  
    valid_search_bys=['all','name','metrics']
    if search_by not in valid_search_bys:
        raise Exception("Error search_by '%s' invalid. Valid options: '%s'" % (search_by,str(valid_search_bys)))  
    valid_match_invert=['match','invert']
    if match_invert not in valid_match_invert:
        raise Exception("Error match_invert '%s' invalid. Valid options: '%s'" % (match_invert,str(valid_match_invert)))  
    if match_invert == "match":
        search_results=([x for x in my_alarms if search_string in str(x)])
    elif match_invert == "invert":
        search_results=([x for x in my_alarms if search_string not in str(x)])
    if return_type == "full_alarm":
       return search_results
    if return_type == "name":
       return [x['AlarmName'] for x in search_results]

def filter_composite_alarms(alarms, search_string, match_invert="match", search_by="all", return_type="full_alarm"):
    """ 
    This method is used to perform filters on a list of alarms and return the result(s) of the filterering.
    Filtering options: search_by=['all','name','metrics'], match_invert=['match','invert'], return_type=['name','full_alarm']
    """
    try:
        if "CompositeAlarms" in alarms.keys():
            my_alarms=alarms['CompositeAlarms']
    except AttributeError:
        my_alarms=alarms
        pass
    valid_return_types=['name','full_alarm']
    if return_type not in valid_return_types:
        raise Exception("Error return_type '%s' invalid. Valid options: '%s'" % (return_type,str(valid_return_types)))  
    valid_search_bys=['all','name','metrics']
    if search_by not in valid_search_bys:
        raise Exception("Error search_by '%s' invalid. Valid options: '%s'" % (search_by,str(valid_search_bys)))  
    valid_match_invert=['match','invert']
    if match_invert not in valid_match_invert:
        raise Exception("Error match_invert '%s' invalid. Valid options: '%s'" % (match_invert,str(valid_match_invert)))  
    if match_invert == "match":
        search_results=([x for x in my_alarms if search_string in str(x)])
    elif match_invert == "invert":
        search_results=([x for x in my_alarms if search_string not in str(x)])
    if return_type == "full_alarm":
       return search_results
    if return_type == "name":
       return [x['AlarmName'] for x in search_results]

def sort_alarms(my_alarms):
    """ Takes a Dict of MetricAlarms and returns them sorted by AlarmName """
    rev_list=[]
    for a in my_alarms:
       str=a['AlarmName'][::-1]
       rev_list.append(str)
    rev_list.sort()
    sorted_alarms=[]
    for r in rev_list:
       str=r[::-1]
       for a in my_alarms:
           if a['AlarmName'] == str:
               sorted_alarms.append(a)
    return sorted_alarms 

def print_composite_alarms(alarms, field="all"):
    """
    Determines if Metric or Composite alarms, and prints via appropriate printer function
    """
    valid_fields=['all','AlarmName','StateValue','ActionsEnabled','TreatMissingData']
    if field not in valid_fields:
        raise Exception("Error field '%s' invalid. Valid options: '%s'" % (field,str(valid_fields)))


def print_metric_alarms(alarms, field="all"):
    """ 
    This method takes a list of alarms and prints their specified config in a prettier format  
    The "field" argument can be specified to show only specific info.
    """
    valid_fields=['all','AlarmName','StateValue','ActionsEnabled','TreatMissingData']
    if field not in valid_fields:
        raise Exception("Error field '%s' invalid. Valid options: '%s'" % (field,str(valid_fields)))  
    if field != "all":
        for a in alarms:
            print(str(a[field]),end="")
            if field != "AlarmName":
                print("," + a['AlarmName'])
            else:
                print()    
        return
    for a in alarms:
      print("AlarmName : " + a['AlarmName'])
      print("  Overview: ")
      print("  - StateValue    : " + str(a['StateValue']))
      print("  - ActionsEnabled: " + str(a['ActionsEnabled']))
      print("  Conditions:")
      if "DatapointsToAlarm" not in a:
          a['DatapointsToAlarm'] = a['EvaluationPeriods']
      if "TreatMissingData" not in a:
          a['TreatMissingData'] = "missing"
      if "ThresholdMetricId" in a: #anomaly detection
          print("  - Threshold:  " + a['ComparisonOperator'])
          print("  - Datapoints: " + str(a['DatapointsToAlarm']) + "/" + str(a['EvaluationPeriods']) + " datapoints")
      else:
          print("  - Threshold:        " + a['ComparisonOperator'] + " " + str(a['Threshold']))
          print("  - Datapoints:       " + str(a['DatapointsToAlarm']) + "/" + str(a['EvaluationPeriods']) + " datapoints")
      print("  - TreatMissingData: " + a['TreatMissingData'])
      print("  Metrics:")
      if "MetricName" in a: #single metric alarms
        print("  - Namespace : " + a['Namespace'])
        print("  - MetricName: " + a['MetricName'])
        print("  - Dimensions: " + str(a['Dimensions']))
      else:
        for m in a['Metrics']: #multi-metrics alarms, anomaly detection alarms
          print("    - " + m['Id'],end=": ")
          if "Expression" in m:
            print(str(m['Expression']))
          else:
            print(str(m['MetricStat']))
      a['AlarmActions'].sort()
      a['OKActions'].sort()
      a['InsufficientDataActions'].sort()
      print("  Actions:")
      print("  - AlarmActions  : " + str(a['AlarmActions']))
      print("  - OKActions     : " + str(a['OKActions']))
      print("  - NoDataActions : " + str(a['InsufficientDataActions']))
      print()

def print_alarms_for_csv(my_alarms):
    """ Method to print alarms for loading into Excel via csv, with summary of name and AlarmActions."""
    for a in my_alarms:
        print(a['AlarmName'],end=";")
        a['AlarmActions'].sort()
        actions=[];
        for act in a['AlarmActions']:
            actions.append(act.split(":")[-1])
        print(str(actions))
		
def backup_alarms(my_alarms, filepath, overwrite=False):
    """ 
    Backs up all avaialble alarms configurations to a file.
    """
    if os.path.exists(filepath) and overwrite == False:
        raise Exception("The filepath specified '%s' already exists, and overwrite=False. Specify overwrite=True, or a different path, to create the backup." % filepath)
    my_alarms_str=json.dumps(my_alarms,default=str)
    f=open(filepath,"w")
    f.write(my_alarms_str)
    f.close()
	
def load_alarms(filepath):
    """ This command will load alarms from a file, into a variable """
    if not os.path.exists(filepath):
        raise FileNotFoundError("File specified does not exist.")
    f=open(filepath,"r")
    try:
        my_alarms=json.load(f)
    except Exception:
        raise Exception("There was an error loading JSON valus from file. Verify validity of alarms file.")
    return my_alarms
	
def filter_sns(sns_list, search_string, match_invert="match"):
    """ Filters sns topics by specified string """
    valid_match_invert=['match','invert']
    if match_invert not in valid_match_invert:
        raise Exception("Error match_invert '%s' invalid. Valid options: '%s'" % (match_invert,str(valid_match_invert))) 
    if match_invert == "match":
        search_results=([x for x in sns_list if search_string in str(x)])
    elif match_invert == "invert":
        search_results=([x for x in sns_list if search_string not in str(x)])
    return search_results
	
def print_sns(my_sns):
    """
    Prints pretty output of an sns topic and it's subscriptions. 
    """
    for s in my_sns:
        my_subs=self.get_sns_subscriptions(s['TopicArn'].split(":")[-1])
        endpoints=[]
        for sub in my_subs['Subscriptions']:
            endpoints.append(sub['Endpoint'])
        endpoints.sort()
        print(s['TopicArn'].split(":")[-1] +","+ str(endpoints))
		
def load_dashboards(filepath):
    """ This command will load dashboards from a file, into a variable """
    if not os.path.exists(filepath):
        raise FileNotFoundError("File specified does not exist.")
    f=open(filepath,"r")
    try:
        my_dashboards=json.load(f)
    except Exception:
        raise Exception("There was an error loading JSON valus from file. Verify validity of alarms file.")
    return my_dashboards
	  
def print_log_groups(log_groups):
    """ Prints specific log group names"""
    for lg in log_groups:
        print(lg['logGroupName'])
		
def filter_metric_filters(metric_filters, search_string, match_invert="match", search_by="all", return_type="full_filter"):
    """ Filters metric filters my given string and filter parameters """
    valid_return_types=['name','full_filter']
    if return_type not in valid_return_types:
        raise Exception("Error return_type '%s' invalid. Valid options: '%s'" % (return_type,str(valid_return_types)))  
    valid_search_bys=['all','name','logGroup']
    if search_by not in valid_search_bys:
        raise Exception("Error search_by '%s' invalid. Valid options: '%s'" % (search_by,str(valid_search_bys)))  
    valid_match_invert=['match','invert']
    if match_invert not in valid_match_invert:
        raise Exception("Error match_invert '%s' invalid. Valid options: '%s'" % (match_invert,str(valid_match_invert))) 
    if match_invert == "match":
        search_results=([x for x in metric_filters if search_string in str(x)])
    elif match_invert == "invert":
        search_results=([x for x in metric_filters if search_string not in str(x)])
    if return_type == "full_filter":
       return search_results
    if return_type == "name":
       return [x['filterName'] for x in search_results]
	   
def print_metric_filters(metric_filters):
    """ Prints metric filters in pretty format for visual parsing """
    for mf in metric_filters:
      print("FilterName : " + mf['filterName'])
      print("  Overview: ")
      print("  - LogGroup     : " + str(mf['logGroupName']))
      print("  - FilterPattern: " + str(mf['filterPattern']))
      print("  Metric Transformations:")
      print("  - Metric Name   : " + mf['metricTransformations'][0]['metricName'])
      print("  - Namespace     : " + mf['metricTransformations'][0]['metricNamespace'])
      print("  - Metric Value  : " + str(mf['metricTransformations'][0]['metricValue']))
      if 'defaultValue' not in mf['metricTransformations'][0]:
        print("  - Default Value : -")
      else:
        print("  - Default Value : " + str(mf['metricTransformations'][0]['defaultValue']))
      if 'unit' not in mf['metricTransformations'][0]:
        print("  - Units         : -")
      else:
        print("  - Units         : " + str(mf['metricTransformations'][0]['unit']))
      if 'dimensions' not in mf['metricTransformations'][0]:
        print("  - Dimensions    : -")
      else:
        print("  - Dimensions    : " + str(mf['metricTransformations'][0]['dimensions']))
      print()
	  
def load_metric_filters(filepath):
    """ This command will load metric filters from a file, into a variable """
    if not os.path.exists(filepath):
        raise FileNotFoundError("File specified does not exist.")
    f=open(filepath,"r")
    try:
        my_metric_filters=json.load(f)
    except Exception:
        raise Exception("There was an error loading JSON valus from file. Verify validity of metric filters file.")
    return my_metric_filters

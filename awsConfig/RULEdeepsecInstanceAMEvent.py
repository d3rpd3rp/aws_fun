#RULEdeepsec-instance-antimalware-event
#Tested with Python 3.6.2

import datetime
import json
from urllib.parse import urlparse

#Deep Security Python SDK by Jefft Thorne
#https://github.com/jeffthorne/DSP3
from dsp3.models.manager import Manager

import boto3

#from mark n.
def aws_config_rule_handler(event, context):
    instance_id = None
    has_policy = False
    detailed_msg = ""
    keys = [ 'invokingEvent', 'ruleParameters', 'resultToken', 'eventLeftScope',\
    'resultToken']
    flag = False
    for key in keys:
        if key in event:
            flag = True
    if flag is False:
        print('AWS Config Rules key in the event object is missing. \
        Requirements: [invokingEvent, ruleParameters, resultToken, \
        eventLeftScope]')
        return { 'result': 'error' }

	# Convert any test events to json (only needed for direct testing through the AWS Lambda Management Console)
    if 'ruleParameters' in event \
        and not type(event['ruleParameters']) == type({}): \
		event['ruleParameters'] = json.loads(event['ruleParameters'])

    if 'invokingEvent' in event \
		and not type(event['invokingEvent']) == type({}): \
		event['invokingEvent'] = json.loads(event['invokingEvent'])

	# Make sure we have the required rule parameters
    if 'ruleParameters' in event:
        if 'deepsecUser' not in event['ruleParameters'] and \
           'deepsecPasswd' not in event['ruleParameters'] and \
           ('deepsecTenant' not in event['ruleParameters'] and \
            'deepsecHostname' not in event['ruleParameters']):
            #need to investigate this return, not sure on purpose
            return { 'requirements_not_met': \
			'Function requires at least deepsecUser, deepsecPasswd, \
			 and either deepsecTenant or deepsecHostname'}
        else:
            print("Credentials for Deep Security passed successfully")

    deepsec_password = event['ruleParameters']['deepsecPasswd']

	# Determine if this is an EC2 instance event
    if 'invokingEvent' in event:
        if 'configurationItem' in event['invokingEvent']:
            if 'resourceType' in event['invokingEvent']['configurationItem'] \
				and event['invokingEvent']['configurationItem'] \
				['resourceType'].lower() == "AWS::EC2::Instance".lower():
				# Something happened to an EC2 instance, we don't worry about what happened
				# the fact that something did is enough to trigger a re-check
				#27 July 2016, I'm not sure we want this as vague as it is, maybe find a trigger
                instance_id = event['invokingEvent']['configurationItem']['resourceId']
                if 'resourceId' in event['invokingEvent']['configurationItem']:
                    if instance_id:
                        print("Target instance [{}]".format(instance_id))
                    else:
                        print('Event is not of resourceType of AWS::EC2::Instance')

    if instance_id:
		# We know this instance ID was somehow impacted, check it's status in Deep Security
        deepsec_tenant = event['ruleParameters']['deepsecTenant'] \
        if 'deepsecTenant' in event['ruleParameters'] else None
        deepsec_hostname = event['ruleParameters']['deepsecHostname'] \
        if 'deepsecHostname' in event['ruleParameters'] else None
        deepsec_manager = None
        print('Passing {}, {}, {}, and {} to deepsecmgr.'.format(event['ruleParameters']['deepsecUser'], \
        event['ruleParameters']['deepsecPasswd'], deepsec_tenant, deepsec_hostname))
        try:
            if deepsec_hostname and deepsec_tenant:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], \
                tenant = deepsec_tenant, hostname = deepsec_hostname)
                print("Successfully authenticated to Deep Security")
            elif deepsec_hostname and not deepsec_tenant:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], hostname = deepsec_hostname)
                print("Successfully authenticated to Deep Security")
            elif deepsec_tenant and not deepsec_hostname:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], tenant = deepsec_tenant)
                print("Successfully authenticated to Deep Security")
            else:
                print("Missing parameters to authenticate to Deep Security Web Service.")
        except Exception:
            print('Authentication Error to Deep Security Manger.')

    if deepsec_manager and instance_id:
        malware_event = None
		#now we need to find the ID to feed to DSP3,
        hosts = deepsec_manager.host_retrieve_all()
        for host in hosts:
            try:
                aws_id = deepsec_manager.host_detail_retrieve(host_id=host['ID'])\
                         ['cloudObjectInstanceId']
                if instance_id.lower().strip() == aws_id:
                    deepsec_manager_instance_id = host['ID']
                    print('the deepsec_manager_instance_id is: {}'.format(host['ID']))
                    malware_event = deepsec_manager.antimalware_event_retreive(time_type = "LAST_HOUR", host_id = deepsec_manager_instance_id)
                    #print('type of mal event {}.'.format(malware_event))
                    #logDate = 2017-07-29 00:21:14+00:00
                    #antiMalwareEvents = None 
                    #print('check for None malware is {}'.format(str(malware_event).find('antiMalwareEvents = None')))
                    #print('check for malware ID is {}'.format(str(malware_event).find('antiMalwareEventID')))
                    #print('type for find is {}'.format(type(str(malware_event).find('antiMalwareEvents = None'))))
                    malware_event_str = str(malware_event)
                    print('***')
                    print(malware_event_str.find('antiMalwareEvents = None'))
                    print(malware_event_str.find('antiMalwareEventID'))
                    print('***')
                    if (malware_event_str.find('antiMalwareEventID') != '-1'):
                        detailed_msg = 'There exists a malware event on this system.'
                        print(detailed_msg)
            except Exception:
                print('derp, system not found or other error.')
    
    deepsec_manager.end_session() # gracefully clean up our Deep Security session

	# Report the results back to AWS Config
    if detailed_msg:
        result = { 'annotation': detailed_msg }
    else:
        result = {}

    client = boto3.client('config')
    if (malware_event_str.find('antiMalwareEvents = None') == '-1'):
        compliance = 'COMPLIANT'
    elif (malware_event_str.find('antiMalwareEventID') != '-1'):
        compliance = 'NON_COMPLIANT'
		#27 July 2017, not sure why this is indented or needs to be...
    try:
        print("Sending results back to AWS Config")
        print('resourceId: {} is {}'.format(event['invokingEvent']['configurationItem']['resourceId'], compliance))

        evaluation = {
			'ComplianceResourceType': event['invokingEvent']['configurationItem']['resourceType'],
			'ComplianceResourceId': event['invokingEvent']['configurationItem']['resourceId'],
			'ComplianceType': compliance,
			'OrderingTimestamp': datetime.datetime.now() }
			
        print('after evaluation assignment 1.')
        
        if detailed_msg:
            evaluation['Annotation'] = detailed_msg
            print('after evaluation assignment 2.')
            
        print(evaluation)
        print('###')
        print([evaluation])
        print('###')
        print(event['resultToken'])

        response = client.put_evaluations(
            Evaluations = [evaluation],
            ResultToken = event['resultToken']
        )
        
        print('response creation.')

        result['result'] = 'success'
        result['response'] = response

    except Exception:
        print("Exception thrown.")
        result['result'] = 'failure'

    print(result)
    return result

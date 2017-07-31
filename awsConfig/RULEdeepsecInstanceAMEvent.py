#RULEdeepsec-instance-antimalware-event
#Tested with Python 3.6.2

import datetime
import json
from urllib.parse import urlparse

#Deep Security Python SDK by Jefft Thorne
#https://github.com/jeffthorne/DSP3
from dsp3.models.manager import Manager

import boto3

#mostly taken from mark nca https://github.com/deep-security/aws-config, 
#ported to version 3
#added a few different cases for compliance
def aws_config_rule_handler(event, context):
    instance_id = None
    has_policy = False
    detailed_msg = ""
    deepsec_manager = None
    stages = []
    malware_event_str = None
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

    #Convert any test events to json (only needed for direct testing through the AWS Lambda Management Console)
    if 'ruleParameters' in event \
        and not type(event['ruleParameters']) == type({}): \
		event['ruleParameters'] = json.loads(event['ruleParameters'])

    if 'invokingEvent' in event \
		and not type(event['invokingEvent']) == type({}): \
		event['invokingEvent'] = json.loads(event['invokingEvent'])

	#Make sure we have the required rule parameters
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
        #log that an instance id was found in aws event
        stages = [('instance id', 1)]
		# We know this instance ID was somehow impacted, check it's status in Deep Security
        deepsec_tenant = event['ruleParameters']['deepsecTenant'] \
        if 'deepsecTenant' in event['ruleParameters'] else None
        deepsec_hostname = event['ruleParameters']['deepsecHostname'] \
        if 'deepsecHostname' in event['ruleParameters'] else None
        deepsec_manager = None
        success_msg = 'Successfully authenticated to Deep Security'
        try:
            if deepsec_hostname and deepsec_tenant:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], \
                tenant = deepsec_tenant, hostname = deepsec_hostname)
                print(success_msg)
            elif deepsec_hostname and not deepsec_tenant:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], hostname = deepsec_hostname)
                print(success_msg)
            elif deepsec_tenant and not deepsec_hostname:
                deepsec_manager = Manager(username = event['ruleParameters']['deepsecUser'],\
                password=event['ruleParameters']['deepsecPasswd'], tenant = deepsec_tenant)
                print(success_msg)
            else:
                print('Missing parameters to authenticate to Deep Security Web Service.')
        except:
            print('Authentication Error to Deep Security Manger.')

    if deepsec_manager and instance_id:
        stages.append(('deepsec_manager authenticate and instance id is object from aws.', 2))
        print(stages)
        malware_event = None
		#now we need to find the ID to feed to DSP3
        hosts = deepsec_manager.host_retrieve_all()
        for host in hosts:
            aws_id = deepsec_manager.host_detail_retrieve(host_id=host['ID'])\
                    ['cloudObjectInstanceId']       
            if instance_id.lower().strip() == aws_id:
                stages.append(('found aws id in deepsec', 3))
                cur_host_status = str(deepsec_manager.host_status(host['ID']))
                if not 'Anti-Malware: Not Activated' in cur_host_status:
                    try:
                        malware_event = deepsec_manager.antimalware_event_retreive(time_type = "LAST_HOUR", host_id = host['ID'])
                        malware_event_str = str(malware_event)
                        if malware_event_str.find('antiMalwareEventID') != -1:
                            detailed_msg = 'There exists a malware event on this system.'
                            print(detailed_msg)
                            break
                    except:
                        print('Exception, error checking malware event from Deep Security.')
                else:
                    detailed_msg = 'Anti-Malware Control Not Activated.'


    client = boto3.client('config')

    #case len(stages) == 0 possibly DNE as awsconfig would not trigger the rule without an instance,
    #or maybe it is possible with the acquisition of the aws id, but then how to report this?
    if (len(stages) == 1):
        #reaching stage 1, array position 0, an aws instance id has been found in aws
        #but no interaction with Deep Security API yet.
        #Return 'General issue.' for lack of more cases.
        compliance = 'NON_COMPLIANT'
        detailed_msg = 'General issue.'
    elif (len(stages) == 2):
        #Deep Security was authenticated but no useful data returned or other problem, 
        #check cloudwatch logs for prints. 
        compliance = 'NON_COMPLIANT'
        detailed_msg = 'Instance found in AWS inventory, unable to confirm status in Deep Security.'
    elif (len(stages) == 3):
        #A few nested cases that could be more deliberately handled
        #Broadly, the idea was to matches the aws id with the deep security aws id; 
        #then there are a few different messages in the routine depending on returns.
        #The default here is when the system is "clean" and contains no anti-malware events.
        #This is the only way to be considered compliant.
        if not detailed_msg:
            compliance = 'COMPLIANT'
            detailed_msg = 'Instance found in Deep Security, but there exist no anti-malware event alerts.'
        else:
            #Various messages are stored previously.
            compliance = 'NON_COMPLIANT'
    else:
        #Catchall for something else...
        compliance = 'NON_COMPLIANT'
        detailed_msg = 'Instance status unknown.'

    # Report the results back to AWS Config
    if detailed_msg:
        result = { 'annotation': detailed_msg }
    else:
        result = {}

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
        print("Exception thrown during the send back to AWS Config.")
        result['result'] = 'failure'

    print(result)
    return result

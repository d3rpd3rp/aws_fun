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
	"""
	Primary entry point for the AWS Lambda function
	Verify whether or not the specified instance is protected by a specific
	Deep Security policy
	print() statments are for the benefit of CloudWatch logs & a nod to old school
	debugging ;-)
	"""
	instance_id = None
	has_policy = False
	detailed_msg = ""

	# Make sure the function has been called in the context of AWS Config Rules
	if not event.has_key('invokingEvent') or not event.has_key('ruleParameters') or \
	not event.has_key('resultToken') or not event.has_key('eventLeftScope'):
		print('AWS Config Rules key in the event object is missing. \
		Requirements: [invokingEvent, ruleParameters, resultToken, \
		eventLeftScope]')
		#need to investigate this return, not sure on purpose
		return { 'result': 'error' }

	# Convert any test events to json (only needed for direct testing through the AWS Lambda Management Console)
	if event.has_key('ruleParameters') \
		and not type(event['ruleParameters']) == type({}): \
		event['ruleParameters'] = json.loads(event['ruleParameters'])

	if event.has_key('invokingEvent') \
		and not type(event['invokingEvent']) == type({}): \
		event['invokingEvent'] = json.loads(event['invokingEvent'])

	# Make sure we have the required rule parameters
	if event.has_key('ruleParameters'):
		if not event['ruleParameters'].has_key('deepsecUser') and \
			 not event['ruleParameters'].has_key('deepsecPasswd') and \
			 (not event['ruleParameters'].has_key('deepsecTenant') \
			 and not event['ruleParameters'].has_key('deepsecHostname')):
			 #need to investigate this return, not sure on purpose
			return { 'requirements_not_met': \
			'Function requires at least deepsecUser, deepsecPasswd, \
			 and either deepsecTenant or deepsecHostname'}
		else:
			print("Credentials for Deep Security passed successfully")

	deepsec_password = event['ruleParameters']['deepsecPasswd']

	if not event['ruleParameters'].has_key('deepsecInstanceAntiMalwareEvent'):
		return { 'requirements_not_met': 'Test returns no \
				  Deep Security Policy was provided.' }

	# Determine if this is an EC2 instance event
	if event.has_key('invokingEvent'):
		if event['invokingEvent'].has_key('configurationItem'):
			if event['invokingEvent']['configurationItem'].has_key('resourceType') \
				and event['invokingEvent']['configurationItem'] \
				['resourceType'].lower() == "AWS::EC2::Instance".lower():
				# Something happened to an EC2 instance, we don't worry about what happened
				# the fact that something did is enough to trigger a re-check
				#27 July 2016, I'm not sure we want this as vague as it is, maybe find a trigger
				instance_id = event['invokingEvent']['configurationItem']['resourceId']
				if event['invokingEvent']['configurationItem'].has_key('resourceId'):
					if instance_id:
						print("Target instance [{}]".format(instance_id))
					else:
						print('Event is not of resourceType of AWS::EC2::Instance')

	if instance_id:
		# We know this instance ID was somehow impacted, check it's status in Deep Security
		deepsec_tenant = event['ruleParameters']['deepsecTenant'] \
		if event['ruleParameters'].has_key('deepsecTenant') else None
		deepsec_hostname = event['ruleParameters']['deepsecHostname'] \
		if event['ruleParameters'].has_key('deepsecHostname') else None
		deepsec_manager = None
		try:
			#dsm = Manager(username="username", password="password", tenant="tenant")   #DSaaS Example
			deepsec_manager = deepsecurity.manager.Manager(username = event['ruleParameters']['deepsecUser'],\
			password=event['ruleParameters']['deepsecPasswd'], \
			tenant = deepsecTenant, dsm_hostname = deepsecHostname)
			print("Successfully authenticated to Deep Security")
		except Exception:
			print('Authentication Error to Deep Security Manger.')

	if deepsec_manager and instance_id:
		#now we need to find the ID to feed to DSP3,
		hosts = deepsec_manager.host_retrieve_all()
		for host in hosts:
			try:
				aws_id = deepsec_manager.host_detail_retrieve(host_id=host['ID'])\
						 ['cloudObjectInstanceId']
				if instance_id.lower().strip() is aws_id:
					deepsec_manager_instance_id = host['ID']
					if deepsec_manager_instance_id:
						malware_event = deepsec_manager.antimalware_event_retreive(time_type = "LAST_24_HOURS", host_id = deepsec_manager_instance_id)
						if malware_event:
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
	if malware_event:
		compliance = 'NON_COMPLIANT'
	else:
		compliance = 'COMPLIANT'
		#27 July 2017, not sure why this is indented or needs to be...
	try:
		print("Sending results back to AWS Config")
		print('resourceId: {} is {}'.format(event['invokingEvent']['configurationItem']['resourceId'], compliance))

		evaluation = {
			'ComplianceResourceType': event['invokingEvent']['configurationItem']['resourceType'],
			'ComplianceResourceId': event['invokingEvent']['configurationItem']['resourceId'],
			'ComplianceType': compliance,
			'OrderingTimestamp': datetime.datetime.now() }

		if detailed_msg:
			evaluation['Annotation'] = detailed_msg

		response = client.put_evaluations(
			Evaluations=[evaluation],
			ResultToken=event['resultToken']
		)

		result['result'] = 'success'
		result['response'] = response

	except Exception:
		print("Exception thrown.")
		result['result'] = 'failure'

	print(result)
	return result

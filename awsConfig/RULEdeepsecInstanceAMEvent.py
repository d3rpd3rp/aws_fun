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
    keys = [ 'invokingEvent', 'ruleParameters', 'resultToken', 'eventLeftScope' ]
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
                    malware_event = deepsec_manager.antimalware_event_retreive(time_type = "LAST_24_HOURS", host_id = deepsec_manager_instance_id)
                    print('type of mal event {}.'.format(malware_event))
                    #logDate = 2017-07-29 00:21:14+00:00
                    #antiMalwareEvents = None 
                    if not str(malware_event).find('antiMalwareEvents = None'):
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
    if not str(malware_event).find('antiMalwareEvents = None'):
        compliance = 'NON_COMPLIANT'
    elif str(malware_event).find('antiMalwareEventID'):
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


"""
#[invokingEvent, ruleParameters, resultToken,eventLeftScope]

sample_event = {'version': '1.0', 'invokingEvent': '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"eni-2181a61d","resourceName":null,"resourceType":"AWS::EC2::NetworkInterface","name":"Contains NetworkInterface"},{"resourceId":"sg-6448a81e","resourceName":null,"resourceType":"AWS::EC2::SecurityGroup","name":"Is associated with SecurityGroup"},{"resourceId":"subnet-72752e3b","resourceName":null,"resourceType":"AWS::EC2::Subnet","name":"Is contained in Subnet"},{"resourceId":"vol-0124b39cdd111f169","resourceName":null,"resourceType":"AWS::EC2::Volume","name":"Is attached to Volume"},{"resourceId":"vpc-2ad1264c","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"Is contained in Vpc"}],"configuration":{"amiLaunchIndex":0,"imageId":"ami-a07379d9","instanceId":"i-07549fadb5643fff9","instanceType":"t2.micro","kernelId":null,"keyName":"21_june_key_pair","launchTime":"2017-06-22T16:13:11.000Z","monitoring":{"state":"disabled"},"placement":{"availabilityZone":"us-west-2a","affinity":null,"groupName":"","hostId":null,"tenancy":"default","spreadDomain":null},"platform":null,"privateDnsName":"ip-172-16-10-237.us-west-2.compute.internal","privateIpAddress":"172.16.10.237","productCodes":[],"publicDnsName":"ec2-54-200-213-109.us-west-2.compute.amazonaws.com","publicIpAddress":"54.200.213.109","ramdiskId":null,"state":{"code":16,"name":"running"},"stateTransitionReason":"","subnetId":"subnet-72752e3b","vpcId":"vpc-2ad1264c","architecture":"x86_64","blockDeviceMappings":[{"deviceName":"/dev/xvda","ebs":{"attachTime":"2017-06-22T16:13:12.000Z","deleteOnTermination":true,"status":"attached","volumeId":"vol-0124b39cdd111f169"}}],"clientToken":"jrYch1498147991029","ebsOptimized":false,"enaSupport":true,"hypervisor":"xen","iamInstanceProfile":null,"instanceLifecycle":null,"networkInterfaces":[{"association":{"ipOwnerId":"amazon","publicDnsName":"ec2-54-200-213-109.us-west-2.compute.amazonaws.com","publicIp":"54.200.213.109"},"attachment":{"attachTime":"2017-06-22T16:13:11.000Z","attachmentId":"eni-attach-2d56b6c0","deleteOnTermination":true,"deviceIndex":0,"status":"attached"},"description":"Primary network interface","groups":[{"groupName":"launch-wizard-1","groupId":"sg-6448a81e"}],"ipv6Addresses":[],"macAddress":"06:f9:69:fc:76:4e","networkInterfaceId":"eni-2181a61d","ownerId":"264059100010","privateDnsName":"ip-172-16-10-237.us-west-2.compute.internal","privateIpAddress":"172.16.10.237","privateIpAddresses":[{"association":{"ipOwnerId":"amazon","publicDnsName":"ec2-54-200-213-109.us-west-2.compute.amazonaws.com","publicIp":"54.200.213.109"},"primary":true,"privateDnsName":"ip-172-16-10-237.us-west-2.compute.internal","privateIpAddress":"172.16.10.237"}],"sourceDestCheck":true,"status":"in-use","subnetId":"subnet-72752e3b","vpcId":"vpc-2ad1264c"}],"rootDeviceName":"/dev/xvda","rootDeviceType":"ebs","securityGroups":[{"groupName":"launch-wizard-1","groupId":"sg-6448a81e"}],"sourceDestCheck":true,"spotInstanceRequestId":null,"sriovNetSupport":null,"stateReason":null,"tags":[{"key":"Name","value":"net_test_system"}],"virtualizationType":"hvm"},"supplementaryConfiguration":{},"tags":{"Name":"net_test_system"},"configurationItemVersion":"1.2","configurationItemCaptureTime":"2017-07-28T10:37:17.537Z","configurationStateId":1501238237537,"awsAccountId":"264059100010","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"i-07549fadb5643fff9","resourceName":null,"ARN":"arn:aws:ec2:us-west-2:264059100010:instance/i-07549fadb5643fff9","awsRegion":"us-west-2","availabilityZone":"us-west-2a","configurationStateMd5Hash":"cb59e5590a975813196334d3b7b78b94","resourceCreationTime":"2017-06-22T16:13:11.000Z"},"notificationCreationTime":"2017-07-28T19:47:07.764Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.2"}', 'ruleParameters': '{"deepsecUser":"aws_config","deepsecPasswd":"Jl092016!","deepsecTenant":"Field"}', 'resultToken': 'eyJlbmNyeXB0ZWREYXRhIjpbLTExOCwtNTIsLTkyLDQ4LDEyLDExLDI0LDkyLC0xNywtMTA2LDE4LDU4LC00MCwxMTMsNjYsNTAsMTE0LDM0LC0xMTYsLTQzLC03Niw3MSwtOTMsNiw1OCwtMTA4LDk2LC0xMTAsNzYsLTIsLTcxLC03MiwtOCw1MywtMTA0LDYwLC04Myw5MiwxMTgsLTEwMywyNiwtMTA2LC0yMyw0Nyw3OCwyMCwtOCw0OCw3MCwzNyw5NiwtMTIwLDQ4LDEwNywtNDEsLTk1LDQ2LC04LC05NSwtNDQsNjYsNTYsLTUsMTA1LC0xNCwyMiwtNTksNjAsOTksMTAxLC01NSwtOCwtNjIsNzgsLTU1LC00OSwtMjEsMywtMTE2LDUwLDI3LDAsMTAsMTAwLDU0LDg2LDkyLC0xMjcsMTgsLTExMCwtNDMsMTExLDUsOTgsLTIxLDExMiwtOTUsNzIsLTQ2LDcwLDM4LDMwLDg2LC0zMyw1NSwxMjQsLTkzLC03NSwtMTAyLDEyNywtMTIyLC05Niw5OSwyMSwxMiwtMTA3LDAsNDYsMzMsLTIxLC00NCwxNCwtNzksMTE4LDUwLDczLDUsNjMsLTExOSwtMTIzLDE2LDgwLDQ0LC01NSw1OCwtNDEsMzIsLTQ3LC05Miw1OCw5NywyLC0xMDAsNTksLTU0LC05OCwtNzIsMjMsMTAzLC03NSwxMjIsNDQsLTEwNyw2OCwtODcsLTYsLTMxLC0xMTUsLTEwOCwtMTA2LC0yLC0xMTMsLTEyMCwtMTIsLTExLDUxLDk5LC0xMTgsMCwtMjksLTMyLC05OCwtNTQsLTExOCwxMDQsNzYsMTIzLDEyMiwxMjAsLTczLDU2LDUwLC0yNiw2NSwtODUsODEsLTIwLDY4LDk5LDM0LDIsNDYsLTMwLDQ3LDkzLC00NSw2MiwtNzAsNzUsLTEyNywtMTcsMTI3LC05OCwtNjMsLTk2LDkwLC0xMjYsMTA2LDg0LC0xLDEyNiwtMzMsLTYyLC01OSwxNywyMywxMDgsOTEsNTYsLTUwLC03NCw1MCwtODIsMiw2OCw0OCw1NCwtMTE4LDM5LDgxLC04NiwtMTE4LC03MywyNiwyLC0zNSwtNDEsMTE3LC01NCwtNTYsLTEwMSwtNTEsMTI2LC02NCwtNTcsMjYsLTQ3LC05NywtODQsLTEyNSwyLC0xMTcsMzEsLTExMCwtMjMsMTAxLDEwMiwtMzAsMTA3LC01NCw5NSw5MCwtMTE3LDYsLTQxLC0zNSw5OSwxMDAsLTQwLC04Nyw0Niw0NCwtNiw2MiwtMiwtMTEsODMsLTk0LC02MSwtNjMsLTExLDI4LDE0LC01Nyw1OCwxMSwtMTUsLTQyLC01OSwtOTIsMzYsOTIsODksMzgsLTQ0LDczLDc2LC02NSwtODcsOTcsLTEzLC02NSwtNTYsLTIyLDk3LC0xNCw5MywxMTEsLTQsLTg2LDMsLTEyLDY5LC0xMDgsLTQ5LDcsODgsMTYsMjksLTExLC03NywtMTIwLC05MiwtMTcsLTI1LDExMiwtNzEsNDgsODcsMTE3LDc1LC01NSwxMTAsLTUsLTIyLDIwLDAsNjYsODMsNzgsLTMyLDcwLC05NiwxMTksMiwtODEsLTEyNSwtOTUsNzYsLTE4LDQ3LDYzLC05NywzNiw3LC04NywtNzMsLTc0LC01MiwtNjUsLTEwMCwxMDksNCw4MSw0Miw5LDUsNDMsMywtODcsMjQsLTQ4LDEyNiwtMTE4LC02NCwtODEsLTM4LDExMyw2LC04MCwtMjksMzQsLTEwNywtNzcsMzYsNDIsOTYsODksLTUxLC04Nyw3LDQ0LDM5LDExOCwtMjUsNTksLTcsLTQ5LC0xMjEsLTEwMSw4NSw4NiwtMTEzLDI3LDQ2LC03MywxMDEsLTExOCw2Miw1LC0xOCwtNDcsLTQyLDY3LC0zNiw1LDI3LC0xNiwyNywzNywxMiwtNTksMzMsNTgsOTIsNTgsLTExMCw5NywtMTA5LC0xOSwtMTQsMTI1LC0yMyw4LDgzLC05LDc0LC0xMDksLTEyLC0xMTMsLTM0LC01MCwxMTUsMjAsNjIsLTksNDIsLTEwMCwtMTE1LDg0LC03NSwxNywtNjUsMjQsLTU4LDEwOSwzNiwxNywtMTA2LC00NSwxMTMsMTEsLTYsNzAsMjQsLTc3LC01MiwtNzcsLTQyLDEwNSwtNCwtNTBdLCJtYXRlcmlhbFNldFNlcmlhbE51bWJlciI6MSwiaXZQYXJhbWV0ZXJTcGVjIjp7Iml2IjpbLTEyLC0yMywtMTA0LDg0LC0xMiw1Nyw3MywtOTEsLTEzLDM5LDQ5LC01NywtMTAxLDEyNSwtMTEsLTEwOF19fQ==', 'eventLeftScope': False, 'executionRoleArn': 'arn:aws:iam::264059100010:role/service-role/ConfigLambdaRole', 'configRuleArn': 'arn:aws:config:us-west-2:264059100010:config-rule/config-rule-v4vew0', 'configRuleName': 'chkAM', 'configRuleId': 'config-rule-v4vew0', 'accountId': '264059100010'} 
key_list = ['invokingEvent', 'ruleParameters', 'resultToken', 'eventLeftScope']
for key in key_list:
    if key not in sample_event:
        print ('Key %s not found.' % key)
    elif key in sample_event:
        print('Key %s found.' % key)
"""

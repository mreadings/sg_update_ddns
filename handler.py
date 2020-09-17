import hashlib
import json
import copy
import urllib3
import boto3
import socket


def update_security_group(hostname,secgroup):
    try:
        new_ip_address = socket.gethostbyname(hostname)
    except:
        return {
        "statusCode": 400,
        "body": json.dumps('DNS %s does not exist' % (hostname) )
            }
    else:         
        #print (new_ip_address)
        try:
            client= boto3.client('ec2')
            response= client.describe_security_groups(GroupIds=[secgroup])
            group= response['SecurityGroups'][0]

        except:
            return {
            "statusCode": 400,
            "body": json.dumps('Security group %s does not contain %s' % (secgroup,hostname) )
                }

        for permission in group['IpPermissions']:
            new_permission = copy.deepcopy(permission)
            ip_ranges = new_permission['IpRanges']
            for ip_range in ip_ranges:
                try: 
                    if ip_range['Description'] == hostname:
                        if ip_range['CidrIp'] != "%s/32" % new_ip_address:
                            ip_range['CidrIp'] = "%s/32" % new_ip_address
                            client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[permission])
                            client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[new_permission])
                except KeyError:
                    pass

                
    return {
        "statusCode": 200,
        "body": json.dumps('%s Updated to %s' % (hostname,new_ip_address) )
    }

def lambda_handler(event, context):
    #print (type(event))
    try:
        postdata = json.loads(event['body'])
    except:
        return {
        "statusCode": 400,
        "body": json.dumps({
            "message" : "missing information"}
        )}    
    else:    
        hostname = postdata['hostname']
        secgroup = postdata['secgroup']
    result = update_security_group(hostname,secgroup)
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message" : result}
        )
    }

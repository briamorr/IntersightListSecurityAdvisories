import json
import requests

from intersight_auth import IntersightAuth

#Convert affected object moid into a user recognizable device name
def affectedObjectMoid2Name(moid, type):
    if type == "network.Element":
        url = "/network/ElementSummaries/"
    elif type == "hyperflex.Cluster":
        url = "/hyperflex/Clusters/"
    elif type == "compute.RackUnit" or type == "compute.Blade":
        url = "/compute/PhysicalSummaries/"
    json_body = {
        "request_method": "GET",
        "resource_path": (
                'https://intersight.com/api/v1' + url + moid
        )
    }

    RESPONSE = requests.request(
        method=json_body['request_method'],
        url=json_body['resource_path'],
        auth=AUTH
    )

    advisories = RESPONSE.json()

    if type == "network.Element":
        print(advisories['Name'] + ", " + advisories['Model'] + ", " + advisories['Firmware'] + ", " + advisories['Ipv4Address'])
    elif type == "hyperflex.Cluster":
        url = "/hyperflex/Clusters/"
        print(advisories['ClusterName'])
    elif type == "compute.RackUnit" or type == "compute.Blade":
        print(advisories['Name'] + ", " + advisories['Model'] + ", " + advisories['Firmware'] + ", " + advisories['Ipv4Address'])

#Get affected objects for the security advisory specified in the moid
def getAffectedObjects(moid):
    json_body = {
        "request_method": "GET",
        "resource_path": (
                'https://intersight.com/api/v1/tam/AdvisoryInstances?$inlinecount=allpages&$skip=0&$top=10&$filter=Advisory.Moid eq %27' + moid + '%27&$expand=AffectedObject'
        )
    }

    RESPONSE = requests.request(
        method=json_body['request_method'],
        url=json_body['resource_path'],
        auth=AUTH
    )

    advisories = RESPONSE.json()["Results"]
    for r in advisories:
        affectedObjectMoid2Name(r['AffectedObjectMoid'], r['AffectedObjectType'])

#Get user friendly information from the security advisory moid
def getSecurityAdvisoryDescription(moid):
    json_body = {
        "request_method": "GET",
        "resource_path": (
                'https://intersight.com/api/v1/tam/SecurityAdvisories/' + moid
        )
    }

    RESPONSE = requests.request(
        method=json_body['request_method'],
        url=json_body['resource_path'],
        auth=AUTH
    )

    advisories = RESPONSE.json()
    print("The following devices are affected by: " + advisories['AdvisoryId'])

#Get all security advisories that are environment is affected by
def getApplicableSecurityAdvisories():
    json_body = {
        "request_method": "GET",
        "resource_path": (
                'https://www.intersight.com/api/v1/tam/AdvisoryInstances?$apply=groupby((Advisory), aggregate($count as count))'
        )
    }

    RESPONSE = requests.request(
        method=json_body['request_method'],
        url=json_body['resource_path'],
        auth=AUTH
    )

    advisories = RESPONSE.json()["Results"]

    for r in advisories:
        getSecurityAdvisoryDescription(r['Advisory']['Moid'])
        getAffectedObjects(r['Advisory']['Moid'])
        print("")

#Configure Intersight API token and start finding all devices affected by a security advisory        
AUTH = IntersightAuth(
    secret_key_filename='SecretKey.txt',
    api_key_id='xxxxxxxxx/xxxxx/xxxxxxxxxx'
    )

getApplicableSecurityAdvisories()

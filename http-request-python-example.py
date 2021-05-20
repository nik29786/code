import requests
import json
import sys
import os
import warnings
import pprint
import logging
import time

def RecorderDeleteAllTest(server_ip, user, password):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorders" 
    logging.info("URL: " + url)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.get(url, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        data = response.json()
        numObjs = len(data)
        logging.info("Num Objects of Kind RecorderConfig : %d", numObjs)
        for i in range (len(data)):
            if 'spec' in  data[i]:
                recorderObjectSpec = data[i]['spec']
                if 'tag' in recorderObjectSpec:
                    get_tag = recorderObjectSpec['tag']
                    if get_tag == None or get_tag == "":
                        continue 
                    retStatus = RecorderDeleteTest(server_ip, user, password, get_tag)
                    if retStatus == "PASS":
                        continue
                    elif retStatus == "FAIL":
                        return "FAIL"
        return "PASS"   
    elif response.status_code == 400:
        return "FAIL"
    elif response.status_code == 404:
        return "FAIL"
    return "FAIL"

def RecorderDeleteTest(server_ip, user, password, tag):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorders/" + tag
    logging.info("Delete URL: " + url)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.delete(url, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        time.sleep(1)
        hwurl = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/hwrecorderdpinstances/" + tag
        get_response = requests.get(hwurl, verify=False, auth=(user,password))
        if get_response.status_code == 404:
            logging.info("Successfuly did a Delete of tag : " + tag)
            return "PASS"
        logging.info("Failed.. Hwinstance recorder present for tag : " + tag)
        return "FAIL"
    elif response.status_code == 400:
        logging.info("Failed code 400 for Delete of tag : " + tag)
        return "FAIL"
    elif response.status_code == 404:
        logging.info("Failed code 404 for Delete of tag : " + tag)
        return "FAIL"
    logging.info("Unknown Failure Delete of tag : " + tag)
    return "FAIL"

def RecorderUpdateTest(server_ip, user, password, tag):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorders/" + tag
    logging.info("Config URL: " + url)

    fileObj = open("apprecorderd_recorder_example_json")
    recorderObj = json.load(fileObj)
    logging.info(recorderObj)
    if 'spec' in recorderObj.keys():
        spec = recorderObj['spec']
        if 'endTime' in spec.keys():
            spec['endTime'] = "Now"
            recorderObj['spec'] = spec
    else:
        logging.critical("spec field does not exist in object, its mandatory")
        return "ERROR", None

    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.put(url, data=json.dumps(recorderObj), headers={"Content-Type": "application/json"}, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        logging.info("Successfuly did a UPDATE of tag : " + tag)
    elif response.status_code == 400:
        jstr = json.dumps(recorderObj)
        logging.error("Bad Request: " + jstr)
    elif response.status_code == 404:
        jstr = json.dumps(recorderObj)
        logging.error("Bad URL: " + response.url)

    if response.status_code == 400:
        logging.info("Get all Objects")
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        numObjs = len(data)
        logging.info("Num Objects of Kind RecorderConfig : %d", numObjs)
        for i in range (len(data)):
            if 'spec' in  data:
                recorderObjectSpec = data['spec']
                if 'tag' in recorderObjectSpec:
                    get_tag = recorderObjectSpec['tag']
                    if get_tag == None:
                        continue
                    logging.info("Got tag:" + get_tag)
                    if get_tag == tag:
                        logging.info("Object with same tag: " + tag + " already exists")
                        logging.info(data)
                        return "FAIL", None

    if response.status_code == 200 or response.status_code == 201:
        time.sleep(1)
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        if 'status' in data:
            recorderStatus = data['status']
            recorderSpec = data['spec']
            get_tag = recorderSpec['tag']
            if recorderSpec['endTime'] != "Now":
                logging.info("endTime update Failed")
                return "FAIL", None
            Endtime = recorderSpec['endTime']
            if 'status' in recorderStatus:
                get_status = recorderStatus['status']
                if Endtime == "Now" and recorderStatus['operStatus'] == "Off" and recorderStatus['dpdkStatus'] == "Success" and recorderStatus['vppStatus'] == "Success":
                    logging.info("Update Configuration successful for tag" + tag + ".")
                    return "PASS", tag
                else:
                    logging.info("Update Configuration status - not success for tag " + tag + " operStatus = " + recorderStatus['operStatus'] + " dpdkStatus = " + recorderStatus['dpdkStatus'] + " vppStatus = " + recorderStatus['vppStatus'])
                    return "FAIL", None
    return "FAIL", None

def RecorderAddTest(server_ip, user, password):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorders"
    logging.info("Config URL: " + url)

    fileObj = open("apprecorderd_recorder_example_json")
    recorderObj = json.load(fileObj)
    logging.info(recorderObj)
    tag = None
    if 'spec' in recorderObj.keys():
        spec = recorderObj['spec']
        if 'tag' in spec.keys():
            tag = spec['tag']
        else:
            logging.critical("tag field does not exist in object, its mandatory")
            return "ERROR", None 
    else:
        logging.critical("spec field does not exist in object, its mandatory")
        return "ERROR", None
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.post(url, data=json.dumps(recorderObj), headers={"Content-Type": "application/json"}, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        logging.info("Successfuly did a CREATE of tag : " + tag)
    elif response.status_code == 400:
        jstr = json.dumps(recorderObj)
        logging.error("Bad Request: " + jstr)
    elif response.status_code == 404:
        jstr = json.dumps(recorderObj)
        logging.error("Bad URL: " + response.url)

    if response.status_code == 400:
        logging.info("Get all Objects")
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        numObjs = len(data)
        logging.info("Num Objects of Kind Recorder : %d", numObjs)
        for i in range (len(data)):
            if 'spec' in  data[i]:
                recorderObjectSpec = data[i]['spec']
                if 'tag' in recorderObjectSpec:
                    get_tag = recorderObjectSpec['tag']
                    if get_tag == None:
                        continue
                    logging.info("Got tag:" + get_tag)
                    if get_tag == tag:
                        logging.info("Object with same tag: " + tag + " already exists")
                        logging.info(data[i])
                        return "FAIL", None

    if response.status_code == 200 or response.status_code == 201:
        time.sleep(1)
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        for i in range (len(data)):
            if 'status' in data[i]:
                recorderStatus = data[i]['status']
                recorderSpec = data[i]['spec']
                get_tag = recorderSpec['tag']
                if tag != get_tag:
                    continue
                if 'operStatus' in recorderStatus:
                    if recorderStatus['operStatus'] == "On" and recorderStatus['dpdkStatus'] == "Success" and recorderStatus['vppStatus'] == "Success":
                        logging.info("Object Configuration successful for tag" + tag + ".")
                        return "PASS", tag
                    else:
                        logging.info("Add Configuration status - not success for tag " + tag + " operStatus = " + recorderStatus['operStatus'] + " dpdkStatus = " + recorderStatus['dpdkStatus'] + " vppStatus = " + recorderStatus['vppStatus'])
                        return "FAIL", None
    return "FAIL", None

def RecorderServicePropertyDeleteTest(server_ip, user, password, serviceId):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorderserviceproperties/" + serviceId
    logging.info("Delete URL: " + url)
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.delete(url, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        time.sleep(1)
        hwurl = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/hwrecorderserviceproperties/" + serviceId
        get_response = requests.get(hwurl, verify=False, auth=(user,password))
        if get_response.status_code == 404:
            logging.info("Successfuly did a Delete of serviceId : " + serviceId)
            return "PASS"
        logging.info("Failed.. hwrecorderserviceproperty present for serviceId : " + serviceId)
        return FAIL
    elif response.status_code == 400:
        logging.info("Failed code 400 for Delete of serviceId : " + serviceId)
        return "FAIL"
    elif response.status_code == 404:
        logging.info("Failed code 404 for Delete of serviceId : " + serviceId)
        return "FAIL"
    logging.info("Unknown Failure Delete of serviceId : " + serviceId)
    return "FAIL"

def RecorderServicePropertyUpdateTest(server_ip, user, password, serviceId):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorderserviceproperties/" + serviceId
    logging.info("Config URL: " + url)

    fileObj = open("apprecorderd_recorderserviceproperty_example_json")
    recSvcPropObj = json.load(fileObj)
    logging.info(recSvcPropObj)
    if 'spec' in recSvcPropObj.keys():
        spec = recSvcPropObj['spec']
        if 'rotateTimeSeconds' in spec.keys():
            spec['rotateTimeSeconds'] = 40
            recSvcPropObj['spec'] = spec
    else:
        logging.critical("spec field does not exist in object, its mandatory")
        return "ERROR", None

    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.put(url, data=json.dumps(recSvcPropObj), headers={"Content-Type": "application/json"}, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        logging.info("Successfuly did a UPDATE of serviceId : " + serviceId)
    elif response.status_code == 400:
        jstr = json.dumps(recSvcPropObj)
        logging.error("Bad Request: " + jstr)
    elif response.status_code == 404:
        jstr = json.dumps(recSvcPropObj)
        logging.error("Bad URL: " + response.url)

    if response.status_code == 400:
        logging.info("Get all Objects")
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        numObjs = len(data)
        logging.info("Num Objects of Kind RecorderServiceProperty : %d", numObjs)
        for i in range (len(data)):
            if 'spec' in  data:
                recSvcPropObjectSpec = data['spec']
                if 'serviceId' in recSvcPropObjectSpec:
                    get_serviceId = recSvcPropObjectSpec['serviceId']
                    if get_serviceId == None:
                        continue
                    logging.info("Got serviceId:" + get_serviceId)
                    if get_serviceId == serviceId:
                        logging.info("Object with same serviceId: " + serviceId + " already exists")
                        logging.info(data)
                        return "FAIL", None

    if response.status_code == 200 or response.status_code == 201:
        time.sleep(1)
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        if 'status' in data:
            recSvcPropStatus = data['status']
            recSvcPropSpec = data['spec']
            get_serviceId = recSvcPropSpec['serviceId']
            if recSvcPropSpec['rotateTimeSeconds'] != 40:
                logging.info("rotateTimeSeconds update Failed")
                return "FAIL", None
            if 'operStatus' in recSvcPropStatus:
                if recSvcPropStatus['operStatus'] == "Success" and recSvcPropStatus['dpdkStatus'] == "Success":
                    logging.info("Update Configuration successful for serviceId" + serviceId + ".")
                    return "PASS", serviceId
                else:
                    logging.info("Update Configuration status - not success for serviceId " + serviceId + " operStatus = " + recSvcPropStatus['operStatus'] + " dpdkStatus = " + recSvcPropStatus['dpdkStatus'])
                    return "FAIL", None
    return "FAIL", None

def RecorderServicePropertyAddTest(server_ip, user, password):
    url = "https://" + server_ip + "/sedgeapi/v1/cisco-npb/apprecorderd/api/npb.argo.cisco.com/v1/recorderserviceproperties"
    logging.info("Config URL: " + url)

    fileObj = open("apprecorderd_recorderserviceproperty_example_json")
    recSvcPropObj = json.load(fileObj)
    logging.info(recSvcPropObj)
    serviceId = None
    if 'spec' in recSvcPropObj.keys():
        spec = recSvcPropObj['spec']
        if 'serviceId' in spec.keys():
            serviceId = spec['serviceId']
        else:
            logging.critical("serviceId field does not exist in object, its mandatory")
            return "ERROR", None 
    else:
        logging.critical("spec field does not exist in object, its mandatory")
        return "ERROR", None
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    response = requests.post(url, data=json.dumps(recSvcPropObj), headers={"Content-Type": "application/json"}, verify=False, auth=(user,password))
    if response.status_code == 200  or response.status_code == 201:
        logging.info("Successfuly did a CREATE of serviceId : " + serviceId)
    elif response.status_code == 400:
        jstr = json.dumps(recSvcPropObj)
        logging.error("Bad Request: " + jstr)
    elif response.status_code == 404:
        jstr = json.dumps(recSvcPropObj)
        logging.error("Bad URL: " + response.url)

    if response.status_code == 400:
        logging.info("Get all Objects")
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        numObjs = len(data)
        logging.info("Num Objects of Kind RecorderServiceProperty : %d", numObjs)
        for i in range (len(data)):
            if 'spec' in  data[i]:
                recSvcPropObjectSpec = data[i]['spec']
                if 'serviceId' in recSvcPropObjectSpec:
                    get_serviceId = recSvcPropObjectSpec['serviceId']
                    if get_serviceId == None:
                        continue
                    logging.info("Got serviceId:" + get_serviceId)
                    if get_serviceId == serviceId:
                        logging.info("Object with same serviceId: " + serviceId + " already exists")
                        logging.info(data[i])
                        return "FAIL", None

    if response.status_code == 200 or response.status_code == 201:
        time.sleep(1)
        get_response = requests.get(url, verify=False, auth=(user,password))
        data = get_response.json()
        for i in range (len(data)):
            if 'status' in data[i]:
                recSvcPropStatus = data[i]['status']
                recSvcPropSpec = data[i]['spec']
                get_serviceId = recSvcPropSpec['serviceId']
                if serviceId != get_serviceId:
                    continue
                if 'operStatus' in recSvcPropStatus:
                    if recSvcPropStatus['operStatus'] == "Success" and recSvcPropStatus['dpdkStatus'] == "Success":
                        logging.info("Object Configuration successful for serviceId" + serviceId + ".")
                        return "PASS", serviceId
                    else:
                        logging.info("Add Configuration status - not success for serviceId " + serviceId + " operStatus = " + recSvcPropStatus['operStatus'] + " dpdkStatus = " + recSvcPropStatus['dpdkStatus'])
                        return "FAIL", None
    return "FAIL", None

if __name__ == "__main__":
    os.system("rm apprecorderd-testlog.log")
    logging.basicConfig(filename="apprecorderd-testlog.log", encoding='utf-8', level=logging.DEBUG)
    server_ip = os.environ.get('MY_ND_IP')
    if server_ip == None:
        logging.critical("export MY_ND_IP to the IP Address of your ND Testbed.")
        sys.exit("export MY_ND_IP, MY_ND_USER, MY_ND_PASSWD with appropriate values.")
    logging.info("ServerIP: " + server_ip)
    user = os.environ.get('MY_ND_USER')
    password = os.environ.get('MY_ND_PASSWD')
    logging.info("username:password:  " + user + ":" + password + "\n")
    if user == None or password == None:
        logging.error("export values for MY_ND_USER or MY_ND_PASSWD not present. Please fix them and retry.")
        sys.exit("export MY_ND_IP, MY_ND_USER, MY_ND_PASSWD with appropriate values.")
    
    retStatus, tag = RecorderAddTest(server_ip, user, password)
    if tag == None:
        logging.error("Tag not returned by RecorderAddTest - FAIL")
    print("Testcase: RecorderAddTest:     " + retStatus)
    if retStatus == "PASS":
        retStatus, tag = RecorderUpdateTest(server_ip, user, password, tag)
        print("Testcase: RecorderUpdateTest:     " + retStatus)
    if retStatus == "PASS":
        retStatus = RecorderDeleteTest(server_ip, user, password, tag)
        print("Testcase: RecorderDeleteTest:     " + retStatus)
    if retStatus == "PASS":
        retStatus, tag = RecorderServicePropertyAddTest(server_ip, user, password)
        if tag == None:
            logging.error("Tag not returned by RecorderServicePropertyAddTest - FAIL")
        print("Testcase: RecorderServicePropertyAddTest:     " + retStatus)
    if retStatus == "PASS":
        retStatus, tag = RecorderServicePropertyUpdateTest(server_ip, user, password, tag)
        print("Testcase: RecorderServicePropertyUpdateTest:     " + retStatus)
    if retStatus == "PASS":
        retStatus = RecorderServicePropertyDeleteTest(server_ip, user, password, tag)
        print("Testcase: RecorderServicePropertyDeleteTest:     " + retStatus)

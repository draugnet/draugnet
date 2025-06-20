from redis import Redis
from fastapi.responses import JSONResponse, PlainTextResponse
from pymisp import PyMISP, MISPEvent, MISPEventReport, MISPObject
from fastapi import HTTPException
from config.settings import misp_config, redis_config, draugnet_config
import random
import string
import re
import os
import time
import json
import logging
from typing import Optional

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OBJECTS_DIR = os.path.join(BASE_DIR, "misp-objects", "objects")

def is_valid_template_name(name: str) -> bool:
    """Allow only alphanumeric characters and dashes."""
    return re.match(r'^[a-zA-Z0-9\-]+$', name) is not None

def get_redis():
    try:
        redis = Redis(host=redis_config['host'], port=redis_config['port'], db=redis_config['db'])
        return redis
    except:
        print("Could not connect to redis.")
        return None

def get_misp():
    try:
        pymisp = PyMISP(misp_config['url'], misp_config['key'], misp_config['verifycert'])
        return pymisp
    except:
        print("Could not connect to redis.")
        return None
    
    

def is_authorised():
    # Implement your authorization logic here
    return True

def generate_token():
    # generate random 32 character token
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

# function to store a uuid at a key derived from the passed token in the format message:<token>
def store_token_to_uuid(token: str, uuid: str):
    redis = get_redis()
    if not redis:
        return None
    logger.info("tokens:" + token)
    redis.set("tokens:" + token, uuid)
    touch_token(token)
    return True

def token_to_uuid(token: str):
    redis = get_redis()
    if not redis:
        return None
    uuid = redis.get("tokens:" + token)
    if not uuid:
        return None
    return uuid.decode('utf-8')

def touch_token(token: str):
    redis = get_redis()
    if not redis:
        return None
    timestamp = int(time.time())
    redis.set("tokens_update:" + token, timestamp)
    return True

def get_token_timestamp(token: str):
    redis = get_redis()
    if not redis:
        return None
    timestamp = redis.get("tokens_update:" + token)
    if not timestamp:
        return None
    return int(timestamp.decode('utf-8'))

def create_report(raw_text_str: str, event_uuid: Optional[str] = None, event_report_name: Optional[str] = "Draugnet Report submission") -> MISPEventReport:
    # Create and attach a MISP Event Report object
    event_report = MISPEventReport()
    if event_uuid:
        event_report.event_uuid = event_uuid
    event_report.name = event_report_name
    event_report.content = raw_text_str
    return event_report

def extract_report_entities(pymisp: PyMISP, event_uuid: str):
    # Extract entities from a report by its ID
    result = pymisp.direct_call(f"eventReports/extractAllFromReport/{event_uuid}", data="{}")
    return result

def create_misp_event():
    # Create a basic MISP event
    event = MISPEvent()
    event.info = "Draugnet report"
    event.distribution = 0
    event.analysis = 0
    event.threat_level_id = 4
    event.add_tag("source:draugnet")
    return event

def save_misp_event(event: MISPEvent, pymisp: PyMISP, logger):
    # Save the MISP event
    try:
        response = pymisp.add_event(event)
        if isinstance(response, dict) and "errors" in response:
            logger.error(f"Error saving event: {json.dumps(response['errors'])}")
            raise HTTPException(status_code=500, detail="Could not save MISP event.")
        return response
    except Exception as e:
        logger.error(f"Exception while saving event: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not save MISP event.")


def get_misp_event(pymisp: PyMISP, logger, uuid:str):
    # Create a basic MISP event
    event = pymisp.get_event(uuid)
    if isinstance(event, dict) and "errors" in event:
        logger.error(f"Error fetching event: {json.dumps(event['errors'])}")
        raise HTTPException(status_code=500, detail="Could not fetch MISP event.")
    return event

def get_misp_object_template_whitelist():
    # Return a list of allowed misp object templates as defined in the settings file under the "misp_object_templates" list. If it is empty or not defined, return null
    if not draugnet_config.get("misp_object_templates"):
        return None
    return draugnet_config["misp_object_templates"]

def add_optional_form_data(event: MISPEvent, options: dict):
    tlp_values = ["tlp:amber", "tlp:green", "tlp:red", "tlp:clear", "tlp:amber+strict", "tlp:unclear"]
    pap_values = ["PAP:CLEAR", "PAP:GREEN", "PAP:AMBER", "PAP:RED"]
    if "title" in options.keys():
        event.info = "Draugnet report: " + options["title"]

    if "distribution" in options.keys():
        event.distribution = options["distribution"]
        if event.distribution == "4" or event.distribution == 4:
            if "sharing_group_id" not in options:
                event.distribution = 0

    if "tlp" in options.keys() and options["tlp"] in tlp_values:
        event.add_tag(options['tlp'])

    if "pap" in options.keys() and options["pap"] in pap_values:
        event.add_tag(options['pap'])

    if "description" in options.keys() and options["description"].strip():
        event.add_event_report("Additional report description", options["description"])

    if "submitter" in options.keys() and options["submitter"].strip():
        logger.info(options["submitter"])
        event.add_tag("submitter:" + options["submitter"].strip())

    return event

def create_misp_object(pymisp: PyMISP, template: str, data: dict):
    try:
        misp_object = MISPObject(template)
        for object_relation in data:
            if isinstance(data[object_relation], str):
                misp_object.add_attribute(object_relation, value=data[object_relation])
            else:
                for value in data[object_relation]:
                    misp_object.add_attribute(object_relation, value=value)
        return misp_object
    except Exception as e:
        logger.error(f"Error creating MISP object: {str(e)}")
        raise HTTPException(status_code=500, detail="Could not create MISP object.")
from redis import Redis
from fastapi.responses import JSONResponse, PlainTextResponse
from pymisp import PyMISP, MISPEvent, MISPEventReport
from fastapi import HTTPException
from settings import misp_config, redis_config, abracadabra_config
import random
import string
import re
import os
import time
import json
import logging

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

def create_report(raw_text_str: str, event_uuid: str):
    # Create and attach a MISP Event Report object
    event_report = MISPEventReport()
    event_report.event_uuid = event_uuid
    event_report.name = "Abracadabra Raw Report submission"
    event_report.content = raw_text_str
    return event_report

def extract_report_entities(pymisp: PyMISP, event_uuid: str):
    # Extract entities from a report by its ID
    result = pymisp.direct_call(f"eventReports/extractAllFromReport/{event_uuid}", data="{}")
    return result

def create_misp_event(pymisp: PyMISP, logger):
    # Create a basic MISP event
    event = MISPEvent()
    event.info = "Shared raw report"
    event.distribution = 0  # Your default distribution level
    event.analysis = 0      # 'Initial'
    event.threat_level_id = 4  # 'Undefined'

    saved_event = pymisp.add_event(event)
    if isinstance(saved_event, dict) and "errors" in saved_event:
        logger.error(f"Error creating event: {json.dumps(saved_event['errors'])}")
        raise HTTPException(status_code=500, detail="Could not create MISP event.")
    return saved_event

def get_misp_event(pymisp: PyMISP, logger, uuid:str):
    # Create a basic MISP event
    event = pymisp.get_event(uuid)
    if isinstance(event, dict) and "errors" in event:
        logger.error(f"Error fetching event: {json.dumps(event['errors'])}")
        raise HTTPException(status_code=500, detail="Could not fetch MISP event.")
    return event

def get_misp_object_template_whitelist():
    # Return a list of allowed misp object templates as defined in the settings file under the "misp_object_templates" list. If it is empty or not defined, return null
    if not abracadabra_config.get("misp_object_templates"):
        return None
    return abracadabra_config["misp_object_templates"]
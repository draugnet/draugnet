from __future__ import annotations
from redis import Redis
from fastapi.responses import JSONResponse, PlainTextResponse
from pymisp import PyMISP, MISPEvent, MISPEventReport, MISPObject
from fastapi import HTTPException
from config.settings import misp_config, redis_config, draugnet_config, modules_config
import random
import string
import re
import os
import time
import json
import logging
from typing import Optional
import importlib
from typing import Any, Dict, Optional, Callable, Awaitable, List
import asyncio

logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OBJECTS_DIR = os.path.join(BASE_DIR, "misp-objects", "objects")

_module_cache: dict[tuple[str, str], Any] = {}

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
        print("Could not connect to MISP.")
        return None
    


def get_module_config(module_type: str, module_name: str) -> Dict[str, Any]:
    try:
        from config.settings import modules_config
    except ImportError:
        return {}

    return (modules_config.get(module_type, {}) or {}).get(module_name, {}) or {}

def is_module_enabled(module_type: str, module_name: str) -> bool:
    cfg = get_module_config(module_type, module_name)
    if not cfg:
        return False
    if "enabled" in cfg:
        return bool(cfg["enabled"])
    return bool(cfg.get("url") and cfg.get("auth_key"))


def get_module(module_type: str, module_name: str):
    key = (module_type, module_name)
    if key in _module_cache:
        return _module_cache[key]

    if not is_module_enabled(module_type, module_name):
        return None

    cfg = get_module_config(module_type, module_name)
    package = f"modules.{module_type}.{module_name}"  # imports the single file

    try:
        mod = importlib.import_module(package)
    except Exception as e:
        logger.exception("Failed to import %s: %s", package, e)
        return None

    if hasattr(mod, "Module"):
        try:
            instance = getattr(mod, "Module")(cfg)
        except Exception as e:
            logger.exception("Failed to instantiate %s.Module: %s", package, e)
            return None

        required_methods = {
            "reporting": ["create_item", "update_item"],
            "enhancements": ["run"]
        }

        # We don’t enforce a strict signature—just ensure methods exist
        for method in required_methods[module_type]:
            if not hasattr(instance, method):
                logger.error("%s.Module missing required method: %s", package, method)
                return None

        _module_cache[key] = instance
        return instance

    logger.error("%s does not export a 'Module' class.", package)
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

def extract_report_entities(pymisp: PyMISP, report_uuid: str):
    # Extract entities from a report by its ID
    result = pymisp.direct_call(f"eventReports/extractAllFromReport/{report_uuid}", data="{}")
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
        response = pymisp.add_event(event, pythonify=True)
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
        event.add_tag("submitter:" + options["submitter"].strip())

    return event

def create_misp_object(pymisp: PyMISP, template: str, data: dict):
    current_stage = "Creating MISP object"
    try:
        misp_object = MISPObject(template)
        for object_relation in data:
            if isinstance(data[object_relation], str):
                current_stage = f"Adding attribute {object_relation}: "
                misp_object.add_attribute(object_relation, value=data[object_relation])
            else:
                for value in data[object_relation]:
                    current_stage = f"Adding attribute {object_relation}: "
                    misp_object.add_attribute(object_relation, value=value)
        return misp_object
    except Exception as e:
        logger.error(f"Error creating MISP object: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Object creation failed. {current_stage} - {str(e)}")
    
async def retrieve_event_by_token(token: str, format: str = "json"):
    uuid = token_to_uuid(token)
    if not uuid:
        raise HTTPException(status_code=404, detail="Could not retrieve the token.")

    pymisp = get_misp()
    r = pymisp.search(
        controller='events',
        eventid=uuid,
        return_format=format,
        includeAnalystData=True,
        published=[True, False],
        includeServerCorrelations=False,
        includeFeedCorrelations=False,
        includeEventCorrelations=False,
        includeGranularCorrelations=False
    )

    if format in ["json", "stix2"]:
        return JSONResponse(content=r)
    else:
        return PlainTextResponse(content=r)
    
def modules_update(context: str, action_type: str, event: Any, token: Optional[str], reports: List[Dict[str, Any]], enhanced_text: Optional[str] = None):
    try:
        loop = asyncio.get_running_loop()
        return loop.create_task(modules_update_async(context, action_type, event, token, reports, enhanced_text))
    except RuntimeError:
        return asyncio.run(modules_update_async(context, action_type, event, token, reports, enhanced_text))
    
async def modules_update_async(context: str, action_type: str, event: Any, token: Optional[str], reports: List[Dict[str, Any]], enhanced_text: Optional[str] = None) -> List[Dict[str, Any]]:
    from config.settings import modules_config

    redis = get_redis()
    reporting_cfg: Dict[str, Dict[str, Any]] = (modules_config.get("reporting") or {})

    results: List[Dict[str, Any]] = []

    for mod_name in reporting_cfg.keys():
        logger.debug(f"Processing module: {mod_name}")
        if not is_module_enabled("reporting", mod_name):
            continue

        mod = get_module("reporting", mod_name)
        if not mod:
            results.append({mod_name: {"ok": False, "error": "module load failed"}})
            continue

        if action_type == "modify" and token:
            external_id = redis.get("modules:" + mod_name + ":token:" + token)
            mod_result = await mod.update_item(context, redis, external_id, event, reports, enhanced_text)
        else:
            mod_result = await mod.create_item(context, redis, token, event, reports, enhanced_text)

        if mod_result:
            results.append({mod_name: {"ok": True}})
        else:
            results.append({mod_name: {"ok": False, "error": "module save failed"}})

    return results


def modules_enhance(action_type: str, context: str, data: Any) -> List[Dict[str, Any]]:
    from config.settings import modules_config  # local import to avoid circulars

    _ = get_redis()  # reserved for future use; no interpretation here
    enh_cfg: Dict[str, Dict[str, Any]] = (modules_config.get("enhancements") or {})
    results: List[Dict[str, Any]] = []

    for mod_name in enh_cfg.keys():
        logger.info("Processing enhancement module: %s", mod_name)
        if not is_module_enabled("enhancements", mod_name):
            continue

        mod = get_module("enhancements", mod_name)
        if not mod:
            logger.error("{mod_name}: module load failed")
            continue

        run_fn = getattr(mod, "run", None)
        if run_fn is None:
            logger.error("{mod_name}: module has no run()")
            continue

        try:
            data = run_fn(action_type, context, data)
        except Exception as e:
            logger.exception("Enhancement module %s failed", mod_name)

    return data

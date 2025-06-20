from fastapi import Request, FastAPI, Query, Body, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pymisp import MISPEvent
from typing import Optional, Literal
from config.settings import misp_config, redis_config, draugnet_config, allowed_origins
import logging
import json
import os
import ssl
import uvicorn

from utils import *

if draugnet_config.get("ssl_cert_path") and draugnet_config.get("ssl_key_path"):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(draugnet_config.get("ssl_cert_path"), keyfile=draugnet_config.get("ssl_key_path"))
if draugnet_config.get("port"):
    port = draugnet_config.get("port")
else:
    port = 8999
    
app = FastAPI()
logger = logging.getLogger('uvicorn.error')
logger.setLevel(logging.DEBUG)


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Could also be ["*"] for all, but it's more secure to specify
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {"message": "Hello World"}

@app.get("/share")
async def root():
    return {
        "formats": {
            "misp": {
                "name": "MISP",
                "description": "MISP format",
                "url": "/share/misp",
                "method": "POST",
            },
            "raw": {
                "name": "Raw",
                "description": "Raw format for freetext parsing",
                "url": "/share/raw",
                "method": "POST"
            },
            "objects": {
                "name": "Objects",
                "description": "Data encoded as MISP Objects",
                "url": "/share/objects",
                "method": "POST"
            }
        }
    }

@app.post("/share/misp")
async def share_misp_event(
    request: Request,
    token: Optional[str] = Query(None, description="Optional access token for editing an existing report")
) -> JSONResponse:
    pymisp = get_misp()
    redis = get_redis()
    if not pymisp or not redis:
        raise HTTPException(status_code=500, detail="Could not connect to MISP or Redis.")
    if not is_authorised():
        raise HTTPException(status_code=403, detail="Not authorized.")

    data = await request.body()
    data = json.loads(data)
    event = MISPEvent()
    if "event" in data:
        data = data["event"]
    if "Event" in data:
        data = data["Event"]
    event.from_dict(**data)

    if data.get("optional"):
        event = add_optional_form_data(event, data["optional"])

    if token:
        uuid = token_to_uuid(token)
        if not uuid:
            raise HTTPException(status_code=404, detail="Invalid token.")
        event.uuid = uuid
        saved_event = pymisp.update_event(event, event_id=uuid)
    else:
        saved_event = pymisp.add_event(event)

    if isinstance(saved_event, dict) and "errors" in saved_event:
        logger.error(f"Error saving event: {json.dumps(saved_event['errors'])}")
        raise HTTPException(status_code=500, detail="Could not save event to MISP.")

    if token:
        touch_token(token)
    else:
        token = generate_token()
        if not store_token_to_uuid(token, saved_event["Event"]["uuid"]):
            raise HTTPException(status_code=500, detail="Could not store token.")

    return {"token": token, "event_uuid": saved_event["Event"]["uuid"], "status": "ok"}

@app.post("/share/raw")
async def post_raw(
    request: Request,
    token: Optional[str] = Query(None, description="Optional access token for editing an existing report")
) -> JSONResponse:
    pymisp = get_misp()
    redis = get_redis()
    if not pymisp or not redis:
        raise HTTPException(status_code=500, detail="Could not connect to MISP or Redis.")
    if not is_authorised():
        raise HTTPException(status_code=403, detail="Not authorized.")
    
    data = await request.body()
    data = json.loads(data)

    if "text" not in data:
        raise HTTPException(status_code=400, detail="Missing 'text' field in request body.")
    
    raw_text_str = data.get("text")

    if not raw_text_str:
        raise HTTPException(status_code=400, detail="Empty report body.")

    if token:
        uuid = token_to_uuid(token)
        if not uuid:
            raise HTTPException(status_code=404, detail="Invalid token.")
        saved_event = pymisp.get_event(uuid)
        if isinstance(saved_event, dict) and "errors" in saved_event:
            logger.error(f"Error getting event: {json.dumps(saved_event['errors'])}")
            raise HTTPException(status_code=403, detail="Invalid MISP event or no access.")
    else:
        event = create_misp_event()
        if data.get("optional"):
            event = add_optional_form_data(event, data["optional"])
        saved_event = save_misp_event(event, pymisp, logger)
        if isinstance(saved_event, dict) and "errors" in saved_event:
            logger.error(f"Error creating event: {json.dumps(saved_event['errors'])}")
            raise HTTPException(status_code=500, detail="Could not create MISP event.")

    event_uuid = saved_event["Event"]["uuid"]
    event_report = create_report(raw_text_str, event_uuid)
    try:
        response = pymisp.add_event_report(event_uuid, event_report)
        if isinstance(response, dict) and "errors" in response:
            logger.error(f"Error adding event report: {json.dumps(response['errors'])}")
            raise HTTPException(status_code=500, detail="Could not attach event report.")
    except Exception as e:
        logger.exception("Exception while adding event report.")
        raise HTTPException(status_code=500, detail=str(e))
    report_uuid = response["EventReport"]["uuid"]

    try:
        result = extract_report_entities(pymisp, report_uuid)
        if isinstance(result, dict) and "errors" in result:
            raise HTTPException(status_code=500, detail="Could not extract entities from report.")
    except Exception as e:
        logger.exception("Exception while extracting entities from report.")
        raise HTTPException(status_code=500, detail=str(e))
    
    if token:
        touch_token(token)
    else:
        token = generate_token()
        if not store_token_to_uuid(token, event_uuid):
            raise HTTPException(status_code=500, detail="Could not store token.")

    return {"token": token, "event_uuid": event_uuid, "status": "ok"}

@app.post("/share/objects")
async def post_objects(
    request: Request,
    token: Optional[str] = Query(None, description="Optional access token for editing an existing report")
) -> JSONResponse:
    pymisp = get_misp()
    redis = get_redis()
    if not pymisp or not redis:
        raise HTTPException(status_code=500, detail="Could not connect to MISP or Redis.")
    if not is_authorised():
        raise HTTPException(status_code=403, detail="Not authorized.")
    
    temp_data = await request.body()
    temp_data = json.loads(temp_data)
    data = {}
    optional = {}

    if "template_name" not in temp_data:
        raise HTTPException(status_code=400, detail="Missing 'template_name' field in request body.")
    template_name = temp_data["template_name"]

    if not token:
        if "optional" in temp_data:
            for key in temp_data['optional']:
                if temp_data['optional'][key] is not None and temp_data['optional'][key] != "" and temp_data['optional'][key] != [] and temp_data['optional'][key] != 'undefined':
                    if key != 'data':
                        optional[key] = temp_data['optional'][key]

    for key in temp_data['data']:
        if temp_data['data'][key] is not None and temp_data['data'][key] != "" and temp_data['data'][key] != [] and temp_data['data'][key] != 'undefined':
            data[key] = temp_data['data'][key]

    if token:
        uuid = token_to_uuid(token)
        if not uuid:
            raise HTTPException(status_code=404, detail="Invalid token.")
        event = pymisp.get_event(uuid, pythonify=True)
        if isinstance(event, dict) and "errors" in event:
            logger.error(f"Error getting event: {json.dumps(event['errors'])}")
            raise HTTPException(status_code=403, detail="Invalid MISP event or no access.")
    else:
        event = create_misp_event()
        if optional:
            event = add_optional_form_data(event, optional)
    
    misp_object = create_misp_object(pymisp, template_name, data)
    event.add_object(misp_object)
    if token:
        saved_event = pymisp.update_event(event)
    else:
        saved_event = pymisp.add_event(event)

    if isinstance(saved_event, dict) and "errors" in saved_event:
        logger.error(f"Error saving event: {json.dumps(saved_event['errors'])}")
        raise HTTPException(status_code=500, detail="Could not save event to MISP.")

    if token:
        touch_token(token)
    else:
        token = generate_token()
        if not store_token_to_uuid(token, saved_event["Event"]["uuid"]):
            raise HTTPException(status_code=500, detail="Could not store token.")

    return {"token": token, "event_uuid": saved_event["Event"]["uuid"], "status": "ok"}

async def _retrieve_event_by_token(token: str, format: str = "json"):
    uuid = token_to_uuid(token)
    if not uuid:
        raise HTTPException(status_code=404, detail="Could not retrieve the token.")

    pymisp = get_misp()
    r = pymisp.search(
        controller='events',
        eventid=uuid,
        return_format=format,
        includeAnalystData=True
    )

    if format in ["json", "stix2"]:
        return JSONResponse(content=r)
    else:
        return PlainTextResponse(content=r)


# GET version (token in path, format in query)
@app.get("/retrieve/{token}")
async def retrieve_event_get(
    token: str,
    format: Literal["json", "csv", "suricata", "text", "stix", "stix2"] = Query("json")
):
    return await _retrieve_event_by_token(token, format)


# POST version (token and format in request body)
@app.post("/retrieve")
async def retrieve_event_post(
    body: dict = Body(..., example={"token": "abc123", "format": "json"})
):
    token = body.get("token")
    format = body.get("format", "json")

    if not token:
        raise HTTPException(status_code=400, detail="Missing token in request body.")
    
    return await _retrieve_event_by_token(token, format)
    
@app.get("/timestamp/{token}")
async def retrieve_last_update_timestamp(
    token: str
):
    timestamp = get_token_timestamp(token)
    if timestamp is None:
        raise HTTPException(status_code=404, detail="Token not found.")
    return PlainTextResponse(content=str(timestamp))


@app.get("/object_templates")
async def get_object_template(
    template: Optional[str] = Query(
        None,
        description="Template name (alphanumeric and dashes only)"
    )
):
    if template:
        if not is_valid_template_name(template):
            raise HTTPException(status_code=400, detail="Invalid template name.")

        template_path = os.path.join(OBJECTS_DIR, template, "definition.json")

        if not os.path.isfile(template_path):
            raise HTTPException(status_code=404, detail="Template not found.")

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                definition = json.load(f)
            return JSONResponse(content=definition)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read template: {str(e)}")

    # If no template is provided, list available templates
    try:
        templates = [
            name for name in os.listdir(OBJECTS_DIR)
            if os.path.isdir(os.path.join(OBJECTS_DIR, name))
               and os.path.isfile(os.path.join(OBJECTS_DIR, name, "definition.json"))
        ]
        template_whitelist = get_misp_object_template_whitelist()
        if template_whitelist:
            templates = [t for t in templates if t in template_whitelist]
        return templates
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list templates: {str(e)}")
    

if __name__ == "__main__":
    if draugnet_config.get("ssl_cert_path") and draugnet_config.get("ssl_key_path"):
        ssl_key_path = draugnet_config.get("ssl_key_path")
        ssl_certfile = draugnet_config.get("ssl_cert_path")
    try:
        uvicorn.run("main:app", host="0.0.0.0", port=port, ssl_keyfile=ssl_key_path, ssl_certfile=ssl_certfile)
    except NameError:
        uvicorn.run("main:app", host="0.0.0.0", port=port)
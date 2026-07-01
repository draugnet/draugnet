# misp config - make sure that you use credentials of a non privileged user meant to handle all requests coming from abracadabra
misp_config = {
    'url': '',
    'key': '',
    'verifycert': True # Set to False if using self-signed certificates or HTTP (but please don't use HTTP in production)
}

modules_config = {
    'reporting': {
        'rtir': {
            # 'url': '', # RTIR URL, e.g. https://my.rtir.instance  - don't add the REST/2.0 part
            # 'auth_key': '', # authey from RTIR
            # 'verifycert': True, # Set to False if using self-signed certificates or HTTP (but please don't use HTTP in production)
            # 'queue': 'Draugnet Reports' # Make sure that the queue exists and is writable by the user associated with the auth_key
        },
        'flowintel': {
            # 'url': '',
            # 'auth_key': '',
            # 'verifycert': True
        }
    },
    "alerting": {
        "email": {
            # "enabled": True,
            # "smtp_host": "localhost",       # SMTP relay hostname
            # "smtp_port": 25,                # SMTP relay port
            # "smtp_tls": False,              # Use implicit TLS (SMTPS, typically port 465)
            # "smtp_starttls": False,         # Use STARTTLS (typically port 587)
            # "smtp_username": "",            # Leave empty if relay does not require auth
            # "smtp_password": "",
            # "sender": "draugnet@example.com",
            # "recipients": ["soc@example.com"],
            # "subject_prefix": "[Draugnet]"
        }
    },
    "enhancements": {
        "ollama": {
            # "enabled": True,
            # "url": "http://path_to_ollama_server:11434",
            # "model": "model_name",
            # "timeout": 120,
            # "temperature": 0.2,
            # "max_tokens": 800,
            #"language": "en", # default output language
            #"style": "concise_risk_intel", # see PROMPT_STYLES below
            # "title_template": "Summary for: ${submission_title}",
            # "prompt_overrides": {}
        }
    }
}

# redis config
redis_config = {
    'host': 'localhost',
    'port': 6379,
    'db': 5
}

# List all allowed frontend origins here
allowed_origins = [
#     "http://localhost:8998",  # Frontend - draugnetUI
#     "http://localhost:8999",  # Backend - draugnet
#     # Add any deployed URLs if needed
#     "http://localhost:5007"
]


# draugnet config
draugnet_config = {
   "misp_object_templates": [
#     add a list of MISP object templates that you want to use - leave empty if you want to use all of them
   ],
   "event_templates": [
#     optional whitelist of event templates to expose (by uuid or name) - leave empty to allow all
#     applies to the "filesystem" template source (see template_config below)
   ],
   "ssl_cert_path": "",
   "ssl_key_path": "",
   "name": "Draugnet" # Name of the instance, used in various places to identify the source when multiple instances are used
}

# event-template data-entry source configuration
#   source:    "filesystem" (default) load <template>/definition.json files from `dir`
#              "misp"                  pull the exposed event-template definitions from the
#                                      configured MISP (reuses misp_config for url + service key)
#   dir:       filesystem source only  directory holding <template>/definition.json files;
#                                      relative paths are resolved against the Draugnet app root
#   cache_ttl: misp source only        seconds to cache the exposed-listing pull (0 disables caching)
template_config = {
    "source": "filesystem",
    "dir": "event-templates",
    "cache_ttl": 300,
}

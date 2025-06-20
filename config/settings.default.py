# misp config - make sure that you use credentials of a non privileged user meant to handle all requests coming from abracadabra
misp_config = {
    'url': '',
    'key': '',
    'verifycert': True
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
   "ssl_cert_path": "",
   "ssl_key_path": ""
}

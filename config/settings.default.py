# misp config - make sure that you use credentials of a non privileged user meant to handle all requests coming from abracadabra
misp_config = {
    'url': '',
    'key': '',
    'verifycert': False
}

# redis config
redis_config = {
    'host': 'localhost',
    'port': 6379,
    'db': 5
}

# List all allowed frontend origins here
allowed_origins = [
#     "http://localhost:8998",  # Frontend origin
#     "http://localhost:8999",  # Backend if accessed via browser (optional)
#     # Add any deployed URLs if needed
#     "http://localhost:5007"
]


# abracadabra config
abracadabra_config = {
   "misp_object_templates": [

   ]
}

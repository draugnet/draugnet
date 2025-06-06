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

# abracadabra config
abracadabra_config = {
   "misp_object_templates": [

   ]
}

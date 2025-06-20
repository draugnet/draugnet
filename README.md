## Draugnet

The light-weight community submission tool for cyber-threat information.

### How it works

Draugnet is a simple API tool that connects to a MISP community and allows users to submit reports in various formats that will be conveyed to MISP.

Draugnet will generate a token for each submission that users can use to retrieve their report along with any updates / comments / new data that the community has added.

### Why?

It's an easy way to report to a CSIRT, a central authority of a sharing community or a partner that you wish to share with - without first negotiating access. It also allows the submitter to keep up to date with changes made to the report and can act as a lightweight collaboration tool.

### Anonymity

In fact, Draugnet supports fully anonymous submissions of data this way. Draugnet only keeps the link between the MISP event UUID generated from the reporting and the token handed back to the user.

### Simple API

- **OpenAPI spec**: simply use a browser and navigate to /docs of your draugnet url and you will get a list of all supported endpoints.
- **Supported submission formats**: You can submit information as plain text, a MISP JSON document or create topic specific data using a set of templates derived from the MISP object repository.
- **Supported retrieval formats**: By default, you will be receiving updates to your data in the MISP JSON format. But you can optionally also fetch the data in any of the supported formats of MISP (such as CSV, Suricata, STIX2, Nibbler).
- **Updating reports**: You can always append new information using any of the supported submission formats by POSTing your new data to be shared to the endpoint you'd use for submissions, but with your token appended as a query string (?token={token})

### Installation

The installation is extremely straight forward, an example given for Ubuntu below:

```
sudo apt install redis python3 python3-venv
git clone https://github.com/draugnet/draugnet
cd draugnet
python3 -m venv ./venv
source .venv/bin/activate
pip install -r requirements
mv config/settings.default.py config/settings.py
```

### Configuring Draugnet

Edit the settings file that is now found at `{draugnet_path}/config/settings.py` and provide draugnet with connection details of your misp instance. Make sure that you use a non privileged user for this (such as a publisher user). It is highly recommended to create or pick a role that has `tag_editor` permissions in MISP.

In the `allowed_origins` setting, add the url through which draugnet is to be reached and if you wish to run draugnet's frontent (draugnetUI), make sure tou add the URL of your draugnetUI server too to the list of whitelisted origins. 

For the insteallation of draugnetUI, head over to (https://github.com/draugnet/draugnetUI)[the draugnet UI repo]

### Launching draugnet

To launch draugnet, simply run (assuming you have the venv enabled):
`python main.py`

To launch draugnet in developer mode (assuming you have the venv enabled):
`fastapi dev main.py`

## Draugnet

<img title="Draugnet logo" src="https://github.com/draugnet/draugnetUI/raw/main/webroot/img/logo_vertical_dark_800.png" width="300" height="300">

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

### Modules

Draugnet comes with modular integrations that can be enabled as needed:

- **Reporting**:  
  - [RTIR](https://github.com/bestpractical/rtir) — Create reports directly in RTIR.  
  - [Flowintel](https://github.com/flowintel/flowintel) — Create reports directly in flowintel. 

- **Enhancement**:  
  - [Ollama](https://ollama.com/) — Leverage LLMs to provide contextual insights and automated text enhancements.  

### Installation

If you wish to install draugnet via docker, head over to the [draugnet-docker repo](https://github.com/draugnet/draugnet-docker)

The native installation is extremely straight forward, an example given for Ubuntu below:

```
sudo apt install redis python3 python3-venv
git clone https://github.com/draugnet/draugnet
cd draugnet
git submodule update --init --recursive
python3 -m venv ./venv
source .venv/bin/activate
pip install -r requirements.txt
mv config/settings.default.py config/settings.py
```

Draugnet bundles three MISP data repositories as git submodules — `misp-objects`
(object templates), `misp-taxonomies` (tag pickers) and `misp-galaxy` (galaxy/cluster
pickers). The `git submodule update --init --recursive` step above populates them; it is
required before the template-driven submission features and their pickers will work.

### Configuring Draugnet

Edit the settings file that is now found at `{draugnet_path}/config/settings.py` and provide draugnet with connection details of your misp instance. Make sure that you use a non privileged user for this (such as a publisher user). It is highly recommended to create or pick a role that has `tag_editor` permissions in MISP.

In the `allowed_origins` setting, add the url through which draugnet is to be reached and if you wish to run draugnet's frontent (draugnetUI), make sure tou add the URL of your draugnetUI server too to the list of whitelisted origins. 

If you want draugnet to run on https (and why wouldn't you?) - simply pass the path to the cert and key files in the draugnet_config section.

#### Event-template submissions

Draugnet can offer reporters a set of guided, CSIRT-authored forms ("event
templates") in addition to the raw submission formats. Templates are loaded from
**one** config-selected source, set in `template_config` in `config/settings.py`
(keys documented inline in `settings.default.py`):

- `source = "filesystem"` (default) — drop `<name>/definition.json` files into
  `template_config["dir"]` (`event-templates/` by default, or point it at your own
  git submodule of curated templates). Optionally restrict which are offered with
  the `draugnet_config["event_templates"]` whitelist (by uuid or name).
- `source = "misp"` — pull only the templates you've **exposed** in the connected
  MISP. In MISP's template builder, flip the *Expose to Draugnet* toggle; Draugnet
  reads them over the `GET /event_templates/exposed` contract using its service key.
  An exposed template is only visible to Draugnet if the service account can read it
  under MISP's normal ACL — keep it in the service account's org, or set the
  template's distribution to *This community*.

Both sources require the bundled submodules (populated by the `git submodule
update --init --recursive` step above), which drive the tag and galaxy pickers.

For the insteallation of draugnetUI, head over to the [draugnetUI repo](https://github.com/draugnet/draugnetUI)

### Launching draugnet

To launch draugnet, simply run (assuming you have the venv enabled):
`python main.py`

To launch draugnet in developer mode (assuming you have the venv enabled):
`fastapi dev main.py`

### Updating draugnet

Updating draugnet is very straight forward (assuming you have the venv enabled).
```
cd /path/to/your/draugnet
git pull origin main
git submodule update --init --recursive
pip install --upgrade -r requirements.txt
```


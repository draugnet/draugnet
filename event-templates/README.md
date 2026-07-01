# Event templates (filesystem source)

This directory is the default location for the **filesystem** event-template
source (`template_config["source"] = "filesystem"` in `config/settings.py`).

Drop one template per subdirectory as `<name>/definition.json`, or a flat
`<name>.json` file directly in this directory. Each file must be a valid
`event-template-v1` definition — the same JSON MISP produces from its template
builder (validated against `schemas/event-template-v1.schema.json` on load;
invalid files are skipped and logged). Templates are addressed by the `uuid`
inside the definition, not by their file name.

The subdirectories shipped here are **examples** copied from the MISP event
template library — replace or delete them with your own CSIRT's templates as
needed. To pull templates from a connected MISP instead of this directory, set
`template_config["source"] = "misp"` (only templates flagged *Expose to
Draugnet* are served).

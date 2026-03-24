# Email Alerting Setup

Draugnet can send alert emails whenever a user submits a new report or updates an existing one. Emails are sent through an SMTP relay host.

## Configuration

Open `config/settings.py` and find the `modules_config` dictionary. Uncomment and fill in the `alerting > email` section:

```python
"alerting": {
    "email": {
        "enabled": True,
        "smtp_host": "mail.example.com",
        "smtp_port": 587,
        "smtp_starttls": True,
        "sender": "draugnet@example.com",
        "recipients": ["soc@example.com", "alerts@example.com"],
        "subject_prefix": "[Draugnet]"
    }
}
```

## Settings Reference

| Setting | Required | Default | Description |
|---------|----------|---------|-------------|
| `enabled` | Yes | — | Set to `True` to activate email alerts |
| `smtp_host` | Yes | `localhost` | SMTP relay hostname |
| `smtp_port` | No | `25` | SMTP relay port |
| `smtp_tls` | No | `False` | Use implicit TLS (SMTPS). Typically used with port 465 |
| `smtp_starttls` | No | `False` | Use STARTTLS. Typically used with port 587 |
| `smtp_username` | No | — | SMTP username, if the relay requires authentication |
| `smtp_password` | No | — | SMTP password, if the relay requires authentication |
| `sender` | No | `draugnet@localhost` | The "From" address on outgoing emails |
| `recipients` | Yes | `[]` | List of email addresses that receive alerts |
| `subject_prefix` | No | `[Draugnet]` | Prefix prepended to every email subject line |

## Common Examples

### Local relay (Postfix / sendmail), no auth

```python
"email": {
    "enabled": True,
    "smtp_host": "localhost",
    "smtp_port": 25,
    "sender": "draugnet@example.com",
    "recipients": ["soc@example.com"]
}
```

### External relay with STARTTLS and authentication

```python
"email": {
    "enabled": True,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_starttls": True,
    "smtp_username": "draugnet@example.com",
    "smtp_password": "app-password-here",
    "sender": "draugnet@example.com",
    "recipients": ["soc@example.com"]
}
```

### Implicit TLS (SMTPS)

```python
"email": {
    "enabled": True,
    "smtp_host": "smtp.example.com",
    "smtp_port": 465,
    "smtp_tls": True,
    "smtp_username": "draugnet@example.com",
    "smtp_password": "app-password-here",
    "sender": "draugnet@example.com",
    "recipients": ["soc@example.com"]
}
```

## What the Emails Contain

Each alert email includes:

- Whether the report is **new** or an **update** to an existing one
- The **submitter** identity (if provided by the user, otherwise "Anonymous")
- The **report title**
- **TLP** and **PAP** markings (if set)
- A brief summary: submission format, number of attributes, objects, and reports

## Disabling

Remove or comment out the `alerting > email` block in `config/settings.py`, or set `"enabled": False`. When disabled, no SMTP connections are made and existing behaviour is unchanged.

# This deployment's persona

`persona.json` is the machine this honeypot pretends to be: the SSH version
string it announces, the hostnames and kernels it claims, the company name on
the website, the shell history in `~/.bash_history`, the credentials in the fake
`wp-config.php`.

It is generated, not committed:

```bash
./deploy/generate-persona.sh
```

## Why it is not in the repository

The engine is public. Every observable constant shipped as source is a
fingerprint — anyone with the code can compare a live host against the defaults
and identify it in a few lines. That is precisely why stock Cowrie is trivially
detected: almost nobody changes its defaults.

Publishing the engine tells an attacker how the honeypot works. Publishing the
persona would tell them how *yours* looks. So this file stays local, and two
deployments of the same release are two different machines.

Absent the file, both readers (`shared/persona.py` and `web/lib/persona.php`)
fall back to built-in defaults so a fresh clone still runs. Those defaults are
public. `deploy/preflight.sh` warns while you are still using them.

## Keep a backup

Regenerating changes the machine attackers see. A host that was `prod-db-01`
running CentOS 7 last week and something else on the same address this week has
told them something. Back this file up alongside your `.env`.

## The honeytokens

`db_password`, `honeytoken_key`, `aws_access_key_id` and `mail_password` are
planted where an attacker will find them — the fake `.env`, `wp-config.php`, the
HTML comments on the homepage. Nothing accepts them, so if one of them ever
appears in a credential-stuffing attempt or a paste dump, you know exactly which
box it was scraped from and roughly when. That inference only works while the
values are unique to this deployment.

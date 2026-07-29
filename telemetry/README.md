# Telemetry

Optional, off by default. Two halves that never run on the same machine:

| | Runs on | Does |
|---|---|---|
| `reporter.py` | each honeypot VPS | Computes aggregate counts and POSTs them |
| `collector.py` | the project host (drosera.lol) | Sums reports, serves one JSON for the site |

`aggregate.py` is shared. It is one short function and it is the complete list
of everything that can ever leave a honeypot box — worth reading before you turn
this on.

## It is off unless you turn it on, twice

The profile has to be requested **and** the flag has to be true:

```bash
# .env
TELEMETRY_ENABLED=true
TELEMETRY_URL=https://drosera.lol/api/report
TELEMETRY_TOKEN=...        # if the collector requires one
TELEMETRY_LABEL=           # optional free-text name for your deployment

docker compose --profile telemetry up -d --build
```

Neither alone does anything. That is deliberate: this project's premise is that
no honeypot container can reach the internet, and people deploy it because they
want a box that talks to nobody. A security appliance that phoned home on its
own would be trading away the exact property it was chosen for.

Turn it off by dropping the profile — `docker compose stop telemetry` — or by
setting `TELEMETRY_ENABLED=false`, in which case the container starts, says so,
and exits.

## What is sent

```json
{
  "schema": 1,
  "instance": "9f2c…",
  "version": "…",
  "reported_at": "2026-07-29T11:00:00+00:00",
  "stats": {
    "days_observed": 3, "unique_ips": 2155, "ips_blocked": 228,
    "events": 33609, "minutes_wasted": 5226.6, "hours_wasted": 87.1,
    "countries": 58,
    "by_service": [{"service": "ssh", "label": "SSH", "events": 2586}]
  }
}
```

Counts, and a random instance id generated locally and stored in
`storage/telemetry-instance.json`. The id is random rather than derived from the
hostname or address — a hash of either would be stable without needing storage,
but it would also be reversible by anyone holding a candidate list, which for
IPv4 is everyone. It exists only so a redeploy does not double-count you.

**Never sent, because it is never read into the process:** addresses,
credentials, payloads, recordings, commands, loot, hostnames, operator identity,
the allowed-IP list, anything from `.env`.

The reporter refuses a non-HTTPS collector URL rather than downgrading, and
reads nothing from the response but its status code.

## Running the collector

On the project host only:

```bash
export TELEMETRY_TOKEN=$(openssl rand -hex 32)
docker compose -f telemetry/compose.collector.yml up -d --build
```

Binds `127.0.0.1:8090`. Put a TLS terminator in front of it:

| Route | |
|---|---|
| `POST /api/report` | Reporters push here |
| `GET /stats.json` | Aggregate for the website |
| `GET /healthz` | |

**Set the token.** Without it anyone who finds the endpoint can POST whatever
numbers they like, and the totals become a claim about who found the endpoint
rather than about how much traffic anyone has seen. Values are clamped either
way, so a hostile report cannot define the scale of a chart — but clamping is a
blast-radius control, not authentication.

Instances that stop reporting for `COLLECTOR_STALE_DAYS` (14) drop out of the
totals instead of inflating them forever.

`days_observed` and `countries` are per-instance and do not sum into anything
meaningful — two deployments each watching 90 days have not observed 180 — so
the aggregate reports the average under `max_days_observed` and
`max_countries` rather than a total.

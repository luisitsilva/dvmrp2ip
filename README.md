# DVMRP Route Listener — Summary

## What it does
A Python daemon that **bridges DVMRP-learned multicast routes into FRRouting (FRR)** so that PIM can use them for RPF (Reverse Path Forwarding) checks.

## Components

**1. `ZAPIClient`** — Talks to Zebra over its Unix socket (`/var/run/frr/zserv.api`) using the ZAPI v3 binary protocol.
- Sends a `ZEBRA_HELLO` to register as a client.
- Encodes routes as `ZEBRA_ROUTE_ADD` / `ZEBRA_ROUTE_DELETE` messages (prefix, nexthop, metric, admin distance 85).
- Labels injected routes as `ZEBRA_ROUTE_BABEL` since DVMRP has no native FRR route type.

**2. `DVMRPRouteManager`** — Learns DVMRP routes and keeps Zebra in sync.
- `_learn_routes_from_dvmrp()` is the integration point. It currently reads `/var/run/dvmrp_routes.txt`; commented-out examples show how to parse `mrouted` output instead. Falls back to two hardcoded test routes if none are found.
- `sync_routes()` adds new/changed routes and deletes stale ones, tracking state in `active_routes`.
- `run()` loops every 30 seconds.

**3. `main()`** — Verifies `frr.service` is active, locates the ZAPI socket (checks several common paths), connects, and runs the manager loop.

## Deployment
The included systemd unit (`dvmrp-listener.service`) starts it after `frr.service`, runs as user `frr`, and auto-restarts on failure.

## Caveats
- The route-learning logic is a **stub** — you must plug in your real DVMRP source (mrouted, multicast probes on 224.0.0.4, or a daemon socket).
- ZAPI is version-sensitive; the struct layouts here are a simplified subset and may need adjustment for your FRR build.
- The hardcoded test routes should be removed in production.

# Grafana Alloy's own public image, no modifications beyond embedding
# this deployment's scrape/remote_write config — see fly.metrics.toml
# and config.alloy. Version pinned deliberately (docs/design.md §21's
# general preference for reproducible deploys, matching every other
# fly.*.toml in this repo).
FROM grafana/alloy:v1.20.0

COPY config.alloy /etc/alloy/config.alloy

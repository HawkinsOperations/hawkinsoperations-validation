# Wazuh Logtest Contracts

This folder contains static CI contracts and controlled synthetic sample events for future Wazuh `wazuh-logtest` validation.

These files do not prove live Wazuh routing, runtime activity, signal observation, public-safe status, production deployment, or dashboard authority. Live Wazuh manager deployment and private runtime validation require a separate approved implementation gate.

The CI-safe verifier checks registry shape, sample availability, blocked claim boundaries, and optional sibling Wazuh XML expectations. If a private runner later provides `wazuh-logtest`, the same registry can be used with the optional execution mode.

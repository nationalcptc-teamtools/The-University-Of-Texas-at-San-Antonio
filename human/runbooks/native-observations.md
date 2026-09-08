# Native observation profiles

The declarative profiles in `profiles/` describe reviewed operator procedures;
they are not arbitrary command templates and are not executed by `cptc-tools`.

`nmap-connect` is limited to one operator-approved port with numeric resolution,
no DNS discovery, scripts, version detection, or broad host scan. Nuclei and
ZAP passive profiles require the reviewed offline observation modules and their
exact input envelope; the active legacy scanner IDs remain unsupported.

A direct bare native command outside the broker can have weaker containment and
must be treated as a human-only observation. Before using one, independently
review the written SOW/ROE, target assignment, exclusions, rate/lockout limits,
output handling, and evidence classification. Do not copy a command containing
credentials or raw response/session values into a terminal or report.

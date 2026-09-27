# Web scripts

| File | Purpose | Commit author |
| --- | --- | --- |
| [`web-tooling.sh`](../setup_scripts/legacy/web-tooling.sh) | Historical web-tool setup script; merged into the [setup master](../setup_scripts/setup_master.sh) | Derya Yavuz; later edited by Moriz82 |
| [`api_sqli.py`](api_sqli.py) | Standalone SQL injection test script | `NetrunnerAlez` |
| [`soap/sarce.py`](soap/sarce.py) | SOAPAction test script | `NetrunnerAlez` |
| [`soap/wdsl-parser.sh`](soap/wdsl-parser.sh) | WSDL parser script | `NetrunnerAlez` |

The archived setup script and remaining web scripts retain their contributed contents. `sarce.py` currently calls a command named `wsdl-parser`, while the committed parser is named `wdsl-parser.sh`. `sarce.py` also contains a fixed WSDL URL. Review both before running them; this move did not test against a network target or silently change either script.

The former Python web coverage application was not restored. Its files remain in Git history.

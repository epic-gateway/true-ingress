#!/bin/bash
# Show content of PFC lookup tables
# syntax: $0

set -Eeo pipefail

/tmp/.acnodal/bin/cli_tunnel get all
/tmp/.acnodal/bin/cli_service get all
    

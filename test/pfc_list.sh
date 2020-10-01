#!/bin/bash
# Show content of PFC lookup tables
# syntax: $0

set -Eeo pipefail

cli_tunnel get all
cli_service get all
    

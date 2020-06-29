# Multiservice tests

Tests to create multiple independent services on same node.
Service instances need to have unique service-id, and _Endpoint_ (IP+PORT).

## test_01.sh

Tests to create 2 services with unique service-ids, same IPs and unique PORTs.

Expected: PASS
Status: PASS

## test_02.sh

Tests to create 2 services with unique service-ids, same IPs and same PORTs.

Expected: FAIL
Status: FAIL

## test_03.sh

Tests to create 2 services with same service-ids, same IPs and unique PORTs.

Expected: FAIL
Status: FAIL

## test_04.sh

Tests to create 2 services with unique service-ids, unique IPs and same PORTs.

Expected: PASS
Status: PASS

## test_05.sh

Tests to create 2 services with unique service-ids, unique IPs and unique PORTs.

Expected: PASS
Status: PASS

## test_06.sh

Tests to create 2 services with same service-ids, unique IPs and unique PORTs.

Expected: FAIL
Status: FAIL


# Multiservice tests

Tests to create multiple independent services on same node.
Service instances need to have unique service-id, and _Endpoint_ (IP+PORT).

## test_01.sh

Creates 2 services with unique service-ids, same IPs and unique PORTs :

    ./test_01.sh

Expected: PASS
Status: PASS

## test_02.sh

Creates 2 services with unique service-ids, same IPs and same PORTs :

    ./test_02.sh

Expected: FAIL
Status: FAIL

## test_03.sh

Creates 2 services with same service-ids, same IPs and unique PORTs :

    ./test_03.sh

Expected: FAIL
Status: FAIL

## test_04.sh

Creates 2 services with unique service-ids, unique IPs and same PORTs :

    ./test_04.sh

Expected: PASS
Status: PASS

## test_05.sh

Creates 2 services with unique service-ids, unique IPs and unique PORTs :

    ./test_05.sh

Expected: PASS
Status: PASS

## test_06.sh

Creates 2 services with same service-ids, unique IPs and unique PORTs :

    ./test_06.sh

Expected: FAIL
Status: FAIL


# basic tests

Tests for topology setup/cleanup, services create/delete, service forwarding create/delete.

### test_01.sh

1) Creates topology based on _basic.cfg_
2) Start HTTP server with service-id 100 on Node1, listening on 1.1.1.1:4000
3) Creates forwarding rules for service-id 100 on EGW which forward 5.5.5.5:3100 to 1.1.1.1:4000
4) Send curl request to 5.5.5.5:3100 requesting _hello_. Service send response with identification.
5) Tear topology down

    ./test_01.sh

Expected: PASS
Status: PASS

### test_02.sh

1) Creates topology based on _basic.cfg_
2) Start HTTP server with service-id 200 on Node2, listening on 2.2.2.2:4000
3) Creates forwarding rules for service-id 200 on EGW which forward 5.5.5.5:3200 to 2.2.2.2:4000
4) Send curl request to 5.5.5.5:3200 requesting _hello_. Service send response with identification.
5) Tear topology down

    ./test_02.sh

Expected: PASS
Status: PASS


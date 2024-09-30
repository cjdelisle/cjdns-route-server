# Cjdns Peer Tester

This tests connectivity to public peers that have registered with the snode.
It requires it's own cjdns node with IPv4 / IPv6 access in order to function.
That cjdns node should be dedicated because it is going to add and remove a
lot of peers. The cjdns that it uses for testing does NOT need to be the same
one that it uses to reach the snode (in fact this is not recommended).

The way this works is:
1. Request public peers from the snode
2. The ones that are older than the re-test time, it attempts to connect to
3. It waits one minute to attempt to get an ESTABLISHED connection
4. It probes to make sure the specified snode is correct
5. It calls back the snode and reports the peer as functioning (or non-functioning)
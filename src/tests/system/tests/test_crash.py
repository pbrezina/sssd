import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.integration
@pytest.mark.importance("low")
@pytest.mark.topology(KnownTopology.Client)
def test_crash_me(client: Client):
    client.host.conn.run("echo 'int main(){*(int*)0=0;}' > crash.c && gcc crash.c -o crash && ./crash")

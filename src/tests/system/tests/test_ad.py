"""
SSSD Client AD tests

:requirement: IDM-SSSD-REQ: Client side performance improvements
"""

from __future__ import annotations

import pytest

from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.topology import KnownTopology


@pytest.mark.importance("critical")
@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_ad__gpo_is_set_to_enforcing(client: Client, ad: AD, sssd_service_user: str):
    """
    :title: Group policy object host base access control is set to enforcing
    :setup:
        1. Create the following users, user, allow_user, allow_user1, deny_user, deny_user1
        2. Create the following groups, allow_group, deny_group
        3. Create the gpo test policy and add allow_user, allow_group and Domain Admins to
            SeInteractiveLogonRight and SeRemoteInteractiveLogonRight keys. Add deny_user
            and deny_group to SeDenyInteractiveLogonRight and SeDenyRemoteInteractiveLogonRight keys.
        4. Link the GPO.
        5. Configure sssd.conf with 'ad_gpo_access_control' = 'enforcing'
        6. Start SSSD
    :steps:
        1. Authenticate allow_user and allow_user1 with both su and ssh
        2. Authenticate user, deny_user and deny_user1 with both su and ssh
    :expectedresults:
        1. User authentication is successful
        2. User authentication is unsuccessful
    :customerscenario: False
    """
    ad.user("user").add()
    allow_user = ad.user("allow_user").add()
    allow_user1 = ad.user("allow_user1").add()
    deny_user = ad.user("deny_user").add()
    deny_user1 = ad.user("deny_user1").add()
    allow_group = ad.group("allow_group").add().add_members([allow_user1])
    deny_group = ad.group("deny_group").add().add_members([deny_user1])

    ad.gpo("test policy").add().policy(
        {
            "SeInteractiveLogonRight": [allow_user, allow_group, ad.group("Domain Admins")],
            "SeRemoteInteractiveLogonRight": [allow_user, allow_group, ad.group("Domain Admins")],
            "SeDenyInteractiveLogonRight": [deny_user, deny_group],
            "SeDenyRemoteInteractiveLogonRight": [deny_user, deny_group],
        }
    ).link()

    client.sssd.set_service_user(sssd_service_user)
    client.sssd.domain["ad_gpo_access_control"] = "enforcing"
    client.sssd.start()

    assert client.auth.ssh.password(username="allow_user", password="Secret123")
    assert client.auth.su.password(username="allow_user", password="Secret123")
    assert client.auth.ssh.password(username="allow_user1", password="Secret123")
    assert client.auth.su.password(username="allow_user1", password="Secret123")
    assert not client.auth.ssh.password(username="user", password="Secret123")
    assert not client.auth.su.password(username="user", password="Secret123")
    assert not client.auth.ssh.password(username="deny_user", password="Secret123")
    assert not client.auth.su.password(username="deny_user", password="Secret123")
    assert not client.auth.ssh.password(username="deny_user1", password="Secret123")
    assert not client.auth.su.password(username="deny_user1", password="Secret123")

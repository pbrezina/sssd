from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.topology import KnownTopology


@pytest.mark.tier(0)
@pytest.mark.topology(KnownTopology.Client)
def test_passkey__register__sssctl(client: Client, moduledatadir: str, testdatadir: str):
    mapping = client.sssctl.passkey_register(
        username="user1",
        domain="ldap.test",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script",
    )
    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip()


@pytest.mark.tier(0)
@pytest.mark.topology(KnownTopology.IPA)
def test_passkey__register__ipa(ipa: IPA, moduledatadir: str, testdatadir: str):
    mapping = (
        ipa.user("user1")
        .add()
        .passkey_add_register(
            pin=123456,
            device=f"{moduledatadir}/umockdev.device",
            ioctl=f"{moduledatadir}/umockdev.ioctl",
            script=f"{testdatadir}/umockdev.script",
        )
    )

    with open(f"{testdatadir}/passkey-mapping") as f:
        assert mapping == f.read().strip()


@pytest.mark.tier(0)
@pytest.mark.topology(KnownTopology.LDAP)
@pytest.mark.topology(KnownTopology.IPA)
def test_passkey__su(client: Client, provider: GenericProvider, moduledatadir: str, testdatadir: str):
    suffix = type(provider).__name__.lower()

    with open(f"{testdatadir}/passkey-mapping.{suffix}") as f:
        provider.user("user1").add().passkey_add(f.read().strip())

    client.sssd.start()

    assert client.auth.su.passkey(
        username="user1",
        pin=123456,
        device=f"{moduledatadir}/umockdev.device",
        ioctl=f"{moduledatadir}/umockdev.ioctl",
        script=f"{testdatadir}/umockdev.script.{suffix}",
    )

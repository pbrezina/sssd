"""
Proxy Provider tests.

:requirement: Proxy Provider
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.base import BaseLinuxRole
from sssd_test_framework.topology import KnownTopology


@pytest.mark.topology(KnownTopology.VagrantFedora)
def test_vagrant(vagrant: BaseLinuxRole):
    pass

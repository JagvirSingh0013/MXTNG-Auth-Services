"""MXTNG Auth Service — standalone, product-generic identity provider.

See ADR-0005 (standalone identity provider), ADR-0006 (JWKS-verifiable JWT keyed
on an auth-minted UUID), and ADR-0007 (products provision accounts just-in-time)
in the ATS repo. This service owns credentials, email, and the global Auth User
Id; it never knows about agencies, roles, or referrals.
"""

__version__ = "0.1.0"

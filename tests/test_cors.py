import pytest


@pytest.mark.asyncio
async def test_login_preflight_allows_production_ats_origin(client):
    response = await client.options(
        "/v1/login/challenge",
        headers={
            "Origin": "https://ats-iota-five.vercel.app",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://ats-iota-five.vercel.app"


@pytest.mark.asyncio
async def test_login_preflight_allows_production_dashboard_origin(client):
    """The origin the product actually signs in from.

    It is reachable through `FALLBACK_CORS_ORIGINS`, so a deployment whose
    `CORS_ORIGINS` predates the move to `dashboard.mxtng.com` still answers the
    preflight instead of locking every user out of sign-in.
    """
    response = await client.options(
        "/v1/login/challenge",
        headers={
            "Origin": "https://dashboard.mxtng.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert (
        response.headers["access-control-allow-origin"] == "https://dashboard.mxtng.com"
    )
    assert response.headers["access-control-allow-credentials"] == "true"


@pytest.mark.asyncio
async def test_login_preflight_refuses_unlisted_origin(client):
    """The allow-list is credentialed, so it must not reflect a stranger back."""
    response = await client.options(
        "/v1/login/challenge",
        headers={
            "Origin": "https://not-our-product.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert "access-control-allow-origin" not in response.headers

import pytest


@pytest.mark.asyncio
async def test_login_preflight_allows_production_ats_origin(client):
    response = await client.options(
        "/v1/login",
        headers={
            "Origin": "https://ats-iota-five.vercel.app",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://ats-iota-five.vercel.app"

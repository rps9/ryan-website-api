import os
import time
import httpx
from fastapi import APIRouter, HTTPException, status, Query, Depends
from jwt_utils import current_admin

router = APIRouter(prefix="/api/spotify")

SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")

spotify_token = {"access_token": None, "expires_at": 0.0}


async def get_access_token() -> str:
    now = time.time()
    if spotify_token["access_token"] and now < spotify_token["expires_at"] - 30:
        return spotify_token["access_token"]

    data = {"grant_type": "client_credentials"}
    auth = (SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET)

    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.post(
            "https://accounts.spotify.com/api/token",
            data=data,
            auth=auth,
        )

    if res.status_code != 200:
        raise HTTPException(status_code=500, detail="spotify auth failed")

    body = res.json()
    spotify_token["access_token"] = body["access_token"]
    spotify_token["expires_at"] = now + body.get("expires_in", 3600)
    return spotify_token["access_token"]


def simplify_track(t: dict) -> dict:
    album = t.get("album", {}) or {}
    images = album.get("images") or []
    # use the smallest image 
    thumb = images[-1]["url"] if images else None
    return {
        "name": t.get("name"),
        "artists": ", ".join(a.get("name", "") for a in (t.get("artists") or [])),
        "image": thumb
    }


async def search_tracks(q: str) -> dict:
    token = await get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    params = {"q": q, "type": "track", "limit": 8, "market": "US"}

    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(
            "https://api.spotify.com/v1/search",
            params=params,
            headers=headers,
        )

    # one retry if token expired
    if res.status_code == 401:
        spotify_token["access_token"] = None
        token = await get_access_token()
        headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                "https://api.spotify.com/v1/search",
                params=params,
                headers=headers,
            )

    if res.status_code == 429:
        # surface as a soft error so UI can show a friendly message
        return {"error": "rate_limited"}

    if res.status_code != 200:
        raise HTTPException(status_code=res.status_code, detail=res.text)

    items = res.json().get("tracks", {}).get("items", [])
    return {"tracks": [simplify_track(t) for t in items]}


@router.get("/search", dependencies=[Depends(current_admin)], status_code=status.HTTP_200_OK)
async def search_tracks_get(
    q: str = Query(..., min_length=1),
):
    return await search_tracks(q)

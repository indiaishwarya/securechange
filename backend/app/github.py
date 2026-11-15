import re
from datetime import datetime

import httpx
from fastapi import HTTPException

from .config import get_settings


def parse_github_url(repository_url: str) -> tuple[str, str]:
    match = re.match(r"https?://github\.com/([^/]+)/([^/#]+?)(?:\.git)?/?$", repository_url.strip())
    if not match:
        raise HTTPException(status_code=400, detail="Use a GitHub repository URL such as https://github.com/org/repository.")
    return match.group(1), match.group(2)


def inspect_github_repository(repository_url: str) -> dict:
    owner, name = parse_github_url(repository_url)
    settings = get_settings()
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    api_root = f"https://api.github.com/repos/{owner}/{name}"
    try:
        with httpx.Client(headers=headers, timeout=20) as client:
            repository_response = client.get(api_root)
            commits_response = client.get(f"{api_root}/commits", params={"per_page": 20})
            pulls_response = client.get(f"{api_root}/pulls", params={"state": "all", "per_page": 20})
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"GitHub request failed: {error}") from error

    if repository_response.status_code >= 400:
        raise HTTPException(status_code=repository_response.status_code, detail="GitHub repository could not be accessed.")
    if commits_response.status_code >= 400 or pulls_response.status_code >= 400:
        raise HTTPException(status_code=commits_response.status_code, detail="GitHub history could not be accessed.")

    repository = repository_response.json()
    commits = []
    for item in commits_response.json():
        commit = item.get("commit", {})
        author = commit.get("author", {})
        commits.append({
            "sha": item.get("sha", ""),
            "short_sha": item.get("sha", "")[:7],
            "subject": (commit.get("message", "").splitlines() or [""])[0],
            "author": author.get("name", "Unknown"),
            "authored_at": author.get("date"),
        })
    pull_requests = []
    for item in pulls_response.json():
        pull_requests.append({
            "number": item.get("number"),
            "title": item.get("title", ""),
            "state": item.get("state", "unknown"),
            "author": (item.get("user") or {}).get("login"),
            "head_sha": (item.get("head") or {}).get("sha"),
            "base_ref": (item.get("base") or {}).get("ref"),
            "url": item.get("html_url"),
            "updated_at": item.get("updated_at"),
        })
    return {
        "name": repository.get("full_name", f"{owner}/{name}"),
        "url": repository.get("html_url", repository_url),
        "default_branch": repository.get("default_branch", "main"),
        "description": repository.get("description"),
        "stars": repository.get("stargazers_count", 0),
        "commits": commits,
        "pull_requests": pull_requests,
    }


def post_pull_request_comment(repository_url: str, pull_number: int, body: str) -> dict:
    owner, name = parse_github_url(repository_url)
    settings = get_settings()
    if not settings.github_token:
        raise HTTPException(status_code=400, detail="GITHUB_TOKEN is required to publish pull-request comments.")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {settings.github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        response = httpx.post(
            f"https://api.github.com/repos/{owner}/{name}/issues/{pull_number}/comments",
            headers=headers,
            json={"body": body},
            timeout=20,
        )
    except httpx.HTTPError as error:
        raise HTTPException(status_code=502, detail=f"GitHub comment request failed: {error}") from error
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail="GitHub pull-request comment could not be published.")
    data = response.json()
    return {"id": data.get("id"), "url": data.get("html_url"), "body": data.get("body")}


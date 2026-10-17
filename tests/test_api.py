import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

if os.getenv('RUN_DB_TESTS') != '1':
    pytest.skip('Requires disposable CI test database', allow_module_level=True)
if urlparse(os.environ.get('DATABASE_URL', '')).path != '/website_test':
    raise RuntimeError('Integration tests require a disposable database named website_test')

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import app
from db import pool
from crypto_utils import hash_password
from jwt_utils import create_access_token

@pytest.fixture(scope='module')
def client():
    # This suite must never be pointed at a production database.
    assert os.environ['DATABASE_URL'].rsplit('/', 1)[-1] == 'website_test'
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL, email_verified BOOLEAN NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user'
        )''')
        cur.execute('TRUNCATE users RESTART IDENTITY')
        for username, role, verified in (
            ('ciuser', 'user', True), ('ciadmin', 'admin', True),
            ('ciunverified', 'user', False),
        ):
            cur.execute('''INSERT INTO users
                (username,email,email_verified,password_hash,role)
                VALUES (%s,%s,%s,%s,%s)''',
                (username, username + '@example.com', verified,
                 hash_password('ci-password-123'), role))
    with TestClient(app) as client:
        yield client


def test_readiness_includes_database(client):
    assert client.get('/api/health').json() == {'ok': True}


def test_readiness_fails_without_leaking_database_errors(client, monkeypatch):
    def unavailable():
        raise RuntimeError('private database connection details')
    monkeypatch.setattr('app.ping', unavailable)
    response = client.get('/api/health')
    assert response.status_code == 503
    assert response.json() == {'detail': 'service unavailable'}


def test_signin_and_role_checks(client):
    response = client.post('/api/auth/signin', json={
        'username': 'ciuser', 'password': 'ci-password-123',
    })
    assert response.status_code == 200
    headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
    assert client.get('/api/db/health', headers=headers).status_code == 403
    admin_headers = {'Authorization': 'Bearer ' + create_access_token(username='ciadmin', role='admin')}
    assert client.get('/api/db/health', headers=admin_headers).json() == {'ok': True}


def test_invalid_and_unverified_credentials(client):
    for username, password, status in (
        ('ciuser', 'wrong-password', 401),
        ('ciunverified', 'ci-password-123', 403),
    ):
        assert client.post('/api/auth/signin', json={
            'username': username, 'password': password,
        }).status_code == status


def test_protected_routes_reject_missing_or_invalid_tokens(client):
    assert client.get('/api/db/health').status_code == 401
    assert client.get('/api/db/health', headers={'Authorization': 'Bearer invalid'}).status_code == 401
    assert client.get('/api/spotify/search?q=test').status_code == 401


def test_validation_and_cors(client):
    assert client.post('/api/auth/signup', json={
        'username': '..invalid', 'password': 'short', 'email': 'bad',
    }).status_code == 422
    response = client.options('/api/auth/signin', headers={
        'Origin': 'https://rps9.net',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type',
    })
    assert response.status_code == 200
    assert response.headers['access-control-allow-origin'] == 'https://rps9.net'

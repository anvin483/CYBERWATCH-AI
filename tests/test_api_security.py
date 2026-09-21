def test_authenticated_mutation_requires_csrf(monkeypatch, isolated_db):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password")
    from app import app
    client = app.test_client()
    login = client.post("/login", data={"username": "admin", "password": "test-password"})
    assert login.status_code == 302
    assert client.post("/api/refresh").status_code == 403

    with client.session_transaction() as session:
        token = session["csrf_token"]
    response = client.post("/api/refresh", headers={"X-CSRF-Token": token})
    assert response.status_code == 200

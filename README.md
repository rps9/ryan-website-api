# API that will be used for my personal website

---

## Stack

* **FastAPI** + Uvicorn
* **Postgres**
* **PBKDF2-SHA256** for password hashing

---

## Services Used
* **Neon** for free database
* **Home server with Nginx, Docker, and Cloudflare Tunnel** for the API and website

## CI/CD

Pull requests run API integration tests against disposable PostgreSQL and smoke
test the production Docker image. Successful merges to `main` publish the tested
image for the home server's deployment timer. See
[deployment setup and rollback](deploy/README.md) for one-time activation.

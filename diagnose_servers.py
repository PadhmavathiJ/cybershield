from app import app

c = app.test_client()

for method in ("GET", "POST"):
    r = c.get("/servers") if method == "GET" else c.post("/servers")
    print(method, "status:", r.status_code, "| redirect:", r.location)

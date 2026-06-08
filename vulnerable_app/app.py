from flask import Flask, request, render_template_string

app = Flask(__name__)

USERS = [
    {"id": 1, "username": "admin", "email": "admin@example.local"},
    {"id": 2, "username": "prakhar", "email": "prakhar@example.local"},
    {"id": 3, "username": "student", "email": "student@example.local"},
]


@app.route("/")
def home():
    return """
    <html>
    <head>
        <title>thebugbounty Test Lab</title>
    </head>
    <body>
        <h1>thebugbounty Local Test Lab</h1>
        <p>This is a harmless local vulnerable app for scanner testing.</p>

        <ul>
            <li><a href="/search?q=test">Search Page - Reflected XSS Test</a></li>
            <li><a href="/user?id=1">User Page - SQLi Error Test</a></li>
            <li><a href="/login">Login Form Test</a></li>
            <li><a href="/safe">Safe Page</a></li>
        </ul>
    </body>
    </html>
    """


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return f"""
    <html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>

        <form method="GET" action="/search">
            <input type="text" name="q" placeholder="Search">
            <button type="submit">Search</button>
        </form>

        <a href="/">Back Home</a>
    </body>
    </html>
    """


@app.route("/user")
def user():
    user_id = request.args.get("id", "1")

    if "'" in user_id or '"' in user_id:
        return """
        <html>
        <body>
            <h1>Database Error</h1>
            <p>SQL syntax error near unexpected input.</p>
            <p>mysql_fetch_array() expects parameter 1 to be resource.</p>
        </body>
        </html>
        """, 500

    for user in USERS:
        if str(user["id"]) == user_id:
            return f"""
            <html>
            <body>
                <h1>User Profile</h1>
                <p>Username: {user["username"]}</p>
                <p>Email: {user["email"]}</p>
                <a href="/">Back Home</a>
            </body>
            </html>
            """

    return "<h1>User not found</h1>", 404


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        message = f"Login failed for user: {username}"

    return render_template_string("""
    <html>
    <head><title>Login</title></head>
    <body>
        <h1>Login Page</h1>

        <p>{{ message }}</p>

        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>

        <a href="/">Back Home</a>
    </body>
    </html>
    """, message=message)


@app.route("/safe")
def safe():
    return """
    <html>
    <head><title>Safe Page</title></head>
    <body>
        <h1>Safe Page</h1>
        <p>This page does not reflect user input.</p>
        <a href="/">Back Home</a>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

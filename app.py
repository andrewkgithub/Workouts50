from flask import Flask, render_template, request, redirect, session
from flask_session import Session
from cs50 import SQL
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///workout_tracker.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    """Display the main dashboard or homepage."""
    user_id = session["user_id"]

    # Query the database for 5 most recent workouts by the logged-in user
    workouts = db.execute("SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC LIMIT 5", user_id)

    return render_template("index.html", workouts=workouts)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Clear any existing user session
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username and password were submitted
        if not username or not password:
            return apology("Missing username or password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Invalid username or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # Handle form submission
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate form input
        if not username:
            return apology("Username is required")
        elif not password:
            return apology("Password is required")
        elif password != confirmation:
            return apology("Passwords do not match")

        # Hash the password
        hash = generate_password_hash(password)

        # Insert the new user into the database
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except:
            return apology("Username already exists")

        # Redirect to the login page after registering
        return redirect("/login")

    else:
        # Display the registration form
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/log_workout", methods=["GET", "POST"])
@login_required
def log_workout():

    if request.method == "POST":
        date = request.form.get("date")
        workout_type = request.form.get("type")
        duration = request.form.get("duration")

        # Validate form input
        if not date or not workout_type or not duration:
            return apology("All fields are required")

        user_id = session["user_id"]

        # Insert workout data into the database
        db.execute("INSERT INTO workouts (user_id, date, type, duration) VALUES (?, ?, ?, ?)",
                   user_id, date, workout_type, duration)

        return redirect("/")

    else:
        # Display the workout logging form
        return render_template("log_workout.html")


@app.route("/view_workouts")
@login_required
def view_workouts():

    user_id = session["user_id"]

    # Query the database for workouts by the logged-in user
    workouts = db.execute("SELECT * FROM workouts WHERE user_id = ? ORDER BY date DESC", user_id)

    # Render the workout history in a template
    return render_template("view_workouts.html", workouts=workouts)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow user to change password"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Validate form input
        if not current_password or not new_password or not confirmation:
            return apology("Must provide all password fields")

        if new_password != confirmation:
            return apology("Passwords do not match")

        user_id = session["user_id"]
        user_data = db.execute("SELECT hash FROM users WHERE id = ?", user_id)[0]

        if not check_password_hash(user_data["hash"], current_password):
            return apology("Invalid current password")

        # Update password
        new_hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

        flash("Password changed successfully")
        return redirect("/")

    else:
        return render_template("change_password.html")


@app.route("/delete_workout/<int:workout_id>", methods=["POST"])
@login_required
def delete_workout(workout_id):
    
    # Check if the logged-in user owns the workout
    user_id = session["user_id"]
    workout = db.execute("SELECT * FROM workouts WHERE id = ? AND user_id = ?", workout_id, user_id)

    if not workout:
        return apology("Workout not found or you don't have permission to delete it")

    # Delete the workout from the database
    db.execute("DELETE FROM workouts WHERE id = ?", workout_id)

    return redirect("/view_workouts")

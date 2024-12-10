# Workout Tracker

#### Description
The Workout Tracker is a web-based application designed to help users log, view, and manage their workout routines. This project was developed as part of the CS50x final project and showcases skills in full-stack web development, including user authentication, data management, and responsive design. 

Built with Python, Flask, SQLite, and Bootstrap, the application provides a seamless experience for users to stay on top of their fitness goals.

---

## Key Features

- **User Authentication**: Secure registration, login, and logout functionality.
- **Workout Logging**: Users can log workouts with details such as date, type of exercise, and duration.
- **Workout History**: View a history of logged workouts in reverse chronological order with the ability to delete entries.
- **Password Management**: Users can change their passwords securely to maintain account safety.
- **Responsive Design**: Fully responsive interface using Bootstrap for optimal usability on various devices.

---

## Technologies Used

- **Backend**: Flask (Python)
- **Database**: SQLite
- **Frontend**: HTML, CSS, Bootstrap
- **Authentication**: Werkzeug (password hashing)

---

## File Structure

- **`app.py`**: Contains the core application logic, including routes and database interactions.
- **`helpers.py`**: Helper functions for error handling and login-required decorators.
- **`templates/`**: Contains HTML templates for the application:
  - **`layout.html`**: The base layout used across all pages.
  - **`index.html`**: Displays the dashboard with recent workouts.
  - **`log_workout.html`**: Form for logging new workouts.
  - **`view_workouts.html`**: Displays the workout history.
  - **`change_password.html`**: Form for updating the user's password.
  - **`register.html`** and **`login.html`**: Registration and login forms.
- **`static/styles.css`**: Custom CSS for styling.
- **`workout_tracker.db`**: SQLite database for storing user and workout data.

---

## Installation and Usage

### Prerequisites
- Python 3.7+
- Flask and required libraries:
  ```bash
  pip install flask flask-session cs50 werkzeug
  ```

### Database Setup 
Run the following SQL commands to set up the database schema:
```
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    hash TEXT NOT NULL
);

CREATE TABLE workouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    type TEXT NOT NULL,
    duration INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Running the Application
1. Clone the repository:
  ```
  git clone https://github.com/your-username/workout-tracker.git
  ```
2. Navigate to the project directory:
  ```
  cd workout-tracker
  ```
3. Set the environment variable for Flask:
- Linux/Mac:
  ```
  export FLASK_APP=app.py
  ```
- Windows (Command Prompt):
  ```
  set FLASK_APP=app.py
  ```
- Windows (PowerShell):
  ```
  $env:FLASK_APP = "app.py"
  ```
4. Run the Flask application:
  ```
  flask run
  ```
5. Open your browser and go to http://127.0.0.1:5000/.

# CardioInsight: Smart Heart Disease Prediction Web App

CardioInsight is a full-stack web application that leverages machine learning to predict heart disease risk, provides educational resources, and offers a seamless user experience with secure authentication and password management.

---

## 🚀 Features

- **User Authentication:** Secure signup, login, and password reset via email.
- **Heart Disease Prediction:** AI-powered risk assessment based on user input.
- **Personalized Dashboard:** View predictions, statistics, and prevention tips.
- **Responsive UI:** Modern, mobile-friendly design using Bootstrap and Tailwind CSS.
- **Email Notifications:** Passwords and resets sent securely via Flask-Mail.
- **MongoDB Integration:** All user data and predictions stored securely.

---

## 🗂️ Project Structure

```
ML_Project/
│
├── Frontend/
│   ├── app.py                  # Main Flask application (Flask backend)
│   ├── database.py             # MongoDB database operations
│   ├── requirements.txt        # Python dependencies
│   ├── templates/              # HTML templates (login, signup, home, etc.)
│   └── static/                 # Static files (CSS, images, JS)
│       ├── CSS/
│       └── Images/
│
├── Heart_Disease_Dataset.csv   # Dataset (headers only for transfer)
└── README.md                   # Project documentation
```

- **app.py**: Main Flask backend for the web app.
- **database.py**: Handles all MongoDB user operations (registration, login, password reset).
- **templates/**: Contains all HTML pages (login, signup, home, profile, etc.).
- **static/**: Contains CSS, images, and other static assets.
- **requirements.txt**: All required Python packages for the project.
- **kaggle dataset link**: https://www.kaggle.com/datasets/rishidamarla/heart-disease-prediction/data

---

## 🖥️ Installation & Setup

### 1. Clone the Repository

```sh
git clone <your-repo-url>
cd ML_Project/Frontend
```

### 2. Create a Virtual Environment

- **On macOS/Linux:**
  ```sh
  python3 -m venv .venv
  ```
- **On Windows:**
  ```sh
  python -m venv .venv
  ```

### 3. Activate the Virtual Environment

- **On macOS/Linux:**
  ```sh
  source .venv/bin/activate
  ```
- **On Windows:**
  ```sh
  .venv\Scripts\activate
  ```

### 4. Install Required Packages

```sh
pip install -r requirements.txt
```

### 5. Configure Environment

- **MongoDB:**  
  Ensure MongoDB is running locally (default: `mongodb://localhost:27017/`).  
  [Download MongoDB Community Server](https://www.mongodb.com/try/download/community) if needed.

- **Email Credentials:**  
  Update the email and password in `app.py` for Flask-Mail:
  ```python
  app.config["MAIL_USERNAME"] = "your_email@example.com"
  app.config["MAIL_PASSWORD"] = "your_email_password"
  ```
  > For Gmail, enable "App Passwords" or "Less secure app access".

### 6. Run the Flask App

```sh
python app.py
```

The app will start on [http://localhost:4000](http://localhost:4000).

---

## 💡 Usage Demo

1. **Register:**  
   Sign up with your email. A 6-digit password will be sent to your email.

2. **Login:**  
   Use your email and the received password to log in.

3. **Predict:**  
   Enter your health details to get a heart disease risk prediction.

4. **Forgot Password:**  
   If you forget your password, use the "Forgot Password?" link. A new 6-digit password will be emailed to you.

5. **Profile & Statistics:**  
   View your prediction history and personalized prevention tips.

---

## 📁 Code Structure Explained

- **app.py:**  
  Main Flask app, handles routing, authentication, and email logic.

- **database.py:**  
  MongoDB operations: user creation, password reset, and user lookup.

- **templates/:**  
  - `login.html`, `signup.html`, `forgot.html`: Auth pages with toast notifications.
  - `home.html`: Landing page with guest mode and navigation.
  - `profile.html`, `find.html`: User dashboard and prediction form.

- **static/CSS/:**  
  Custom styles for each page.

- **static/Images/:**  
  App logos, icons, and illustrations.

---

## 🛠️ Troubleshooting

- **MongoDB Not Running:**  
  Start MongoDB with `mongod` in your terminal.

- **Email Not Sending:**  
  Double-check your email credentials and allow less secure apps if using Gmail.

- **Missing Packages:**  
  Run `pip install -r requirements.txt` again in your activated virtual environment.

- **Virtual Environment Not Activating:**  
  - macOS/Linux: `source .venv/bin/activate`
  - Windows: `.venv\Scripts\activate`

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## 📷 Screenshots

Below are some screenshots demonstrating the CardioInsight web app:

### Login Page
![Login Page](static/Images/login_screenshot.png)

### Signup Page
![Signup Page](static/Images/signup_screenshot.png)

**Enjoy using CardioInsight! Stay heart healthy.**
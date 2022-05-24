from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
app = Flask(__name__)

app.config['SECRET_KEY'] = 'YOUR-SECRET-KEY'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# # CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    return User.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash(f'No account for {email} found in database')
            return redirect(url_for('login'))
        user_password = user.password
        if check_password_hash(user_password, password):
            # flash('Logged in successfully.')
            login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash(f'Incorrect password, please try again.')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        salted_hash = generate_password_hash(password)
        if User.query.filter_by(email=email).first():
            flash("You've already signed up with that email, log in instead")
            return redirect(url_for('login'))
        new_user = User(name=name,
                        email=email,
                        password=salted_hash)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful!")
        flash("Please login to view your account")
        return render_template("login.html", just_registered=True)
    return render_template("register.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    # Directory is empty, path is relative, and "as_attachment" is off, so will open up as pdf page
    # return send_from_directory(directory="", path="static/files/cheat_sheet.pdf", as_attachment=False)
    # OR Her way, directory is static, then the rest is relative
    return send_from_directory(directory="static", path="files/cheat_sheet.pdf", as_attachment=False)

if __name__ == "__main__":
    app.run(debug=True)

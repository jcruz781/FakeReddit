from flask import Flask, render_template, request, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SECRET_KEY'] = 'keyword'
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Using Quickstart from flask-sqlalchemy website

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class RegisForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField('Register')

def valid_username(self, username):
    existing_user = User.query.filter_by(username=username.data).first()
    if existing_user:
        raise ValidationError("Username taken, choose a different one.")
    
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder":"Password"})
    submit = SubmitField('Login')

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    desc = db.Column(db.String)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    txtcmt = db.Column(db.String, unique=True, nullable=False)
    topID = db.Column(db.String)

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('Main'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/main", methods=["GET","POST"])
@login_required
def Main():
    if request.method == "POST":
        #adding new topic
        topic = Topic(
            title=request.form["title"], 
            desc=request.form["desc"],
        )
        db.session.add(topic)
        db.session.commit()

    topics = db.session.execute(db.select(Topic)).scalars()
    #for topic in topics:
    #    print(topic.title, topic.desc, topic.id)
    return render_template("indmain.html", topics=topics)

@app.route("/topic/<int:id>", methods=["GET","POST"])
@login_required
def cTopic(id):
    form = LoginForm()
    if request.method == "POST":
        #adding new comment
        comment = Comment(
            txtcmt=request.form["comment"], 
            topID=id
        )
        db.session.add(comment)
        db.session.commit()

    topic = db.get_or_404(Topic, id)
    comments = Comment.query.filter_by(topID=id).all()
    return render_template("topic.html", topic=topic, comments=comments)

app.run(debug=True)

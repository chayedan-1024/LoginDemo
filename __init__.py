import os
from flask import Flask, render_template, url_for, redirect, flash
from flask_login import LoginManager, UserMixin, current_user, \
                        login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, PasswordField,\
                    BooleanField
from wtforms.validators import ValidationError, DataRequired, Length
try:
    from .scripts import get_login_config
except:
    from scripts import get_login_config

# 数据库连接地址
with open("./Config/login.txt", "r") as f:
    encoded_info = f.read()
    login_dict = get_login_config(encoded_info)["login"]
    mysql_user = login_dict["username"]
    mysql_password = login_dict["password"]
database_name = "login_info"
class Config(object):
    # 密钥
    SECRET_KEY = os.environ.get("SECRET_KEY") or "QuLab104!"
    # 数据库
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI") or \
        "mysql://" + mysql_user + ":" + mysql_password+ "@localhost" + "/" + database_name
    SQLALCHEMY_TRACK_MODIFICATION = False

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

login_manager = LoginManager()

# 登录表单
class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[DataRequired()])
    password = PasswordField("密码", validators=[DataRequired()])
    remember_me = BooleanField("记住我")
    submit = SubmitField("登录")

# 数据库模型
# UserMinx 表示通过认证的用户
# is_authenticated: 一个用来表示用户是否通过登录认证的属性
# is_active: 表示用户是否活跃
# is_anonymous: 常规用户False，对特定匿名用户True
class User(UserMixin, db.Model):
    __tablename__ = "user_info"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, name, password, email=None):
        self.username = name
        self.password =  password

    @property
    def password(self):
        raise AttributeError("密码属性不可读")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
login_manager.login_view = "login"
login_manager.init_app(app)


@app.route("/")
def index():
    flash("这是一条闪现信息：请点击登录/login")
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("show_user"))
    form = LoginForm()
    # 数据提交验证
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember_me.data
        # 数据查询
        user = User.query.filter_by(username=username).first()
        if user:
            if username == user.username and user.check_password(password):
                # 保存到session当中
                login_user(user, remember)
                flash("登录成功")
                return redirect(url_for("show_user"))
            else:
                flash("账户名或密码错误")
                redirect(url_for("login"))
        else:
            flash("账户名不存在")
    return render_template("login.html", form=form)

@app.route("/user_info")
def show_user():
    return "hello, " + current_user.username

@app.route("/show_success")
@login_required
def show_():
    return render_template("main.html")

@app.route("/abc")
def logout():
    logout_user()
    return redirect(url_for("index"))

print(Config.SQLALCHEMY_DATABASE_URI)
if __name__ == "__main__":
    app.run()
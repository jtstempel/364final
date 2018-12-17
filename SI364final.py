# Import statements
import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash

# Imports for login management
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/jstempelFinaldb"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# App addition setups
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

# Login configurations setup
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app) # set up login manager

#Models
user_list = db.Table('user_list', db.Column('show_id', db.Integer, db.ForeignKey('info.id')), db.Column('list_id', db.Integer, db.ForeignKey('personal_lists.id')))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))

    my_lists = db.relationship('TVmovieList', backref = 'User')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class TVmovieInfo(db.Model):
    __tablename__ = "info"
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(128))
    rating = db.Column(db.String)
    year = db.Column(db.String)
    plot = db.Column(db.String)
    director = db.Column(db.Integer, db.ForeignKey('director.id'))
    my_ranking = db.Column(db.Integer)

    def __repr__(self):
        return "{}".format(self.title)

class Director(db.Model):
    __tablename__ = "director"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(128))

    def __repr__(self):
        return "{}".format(self.name)

class TVmovieList(db.Model):
    __tablename__ = "personal_lists"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    titles = db.relationship('TVmovieInfo', secondary = user_list, backref = db.backref("personal_lists", lazy = 'dynamic'), lazy = 'dynamic')


#Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class TvmovieForm(FlaskForm):
    search = StringField('Enter a TV or movie title', validators=[Required()])
    ranking = StringField('How would you rank this title? (1 = lowest, 5 = highest)', validators=[Required()])
    submit = SubmitField('Submit')

    def validate_search(self, field):
        special_chars = ["!", "@", "#", "$", "&", "?"]
        for letter in field.data:
            if letter in special_chars:
                raise ValidationError('Do not include special characters in search')

    def validate_ranking(self, field):
        if int(field.data) > 5 or int(field.data) < 1:
            raise ValidationError('Ranking must be between 1 and 5')

class ListForm(FlaskForm):
    name = StringField('List Name',validators=[Required()])
    movie_picks = SelectMultipleField('Movies and shows to include')
    submit = SubmitField("Create List")

class UpdateButtonForm(FlaskForm):
    submit = SubmitField("Update")

class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete")

class UpdateRankForm(FlaskForm):
    update_rank = StringField("Update the ranking", validators=[Required()])
    submit = SubmitField("Update")


#Functions
def get_title_from_omdb(search):
    baseurl = "http://www.omdbapi.com/"
    my_params = {'apikey': 'fb544fd4', 't': search}
    response = requests.get(baseurl, params = my_params)
    my_json = json.loads(response.text)
    return my_json

def get_or_create_title(title, rating, year, plot, director, my_ranking):
    my_title = TVmovieInfo.query.filter_by(title = title).first()
    if my_title:
        return my_title
    else:
        my_title = TVmovieInfo(title=title, rating=rating, year=year, plot=plot, director=director, my_ranking=my_ranking)
        db.session.add(my_title)
        db.session.commit()
        return my_title

def get_or_create_director(name):
    my_director = Director.query.filter_by(name = name).first()
    if my_director:
        return my_director
    else:
        my_director = Director(name = name)
        db.session.add(my_director)
        db.session.commit()
        return my_director

def get_or_create_list(db_session, name, current_user, title_list=[]):
    my_list = TVmovieList.query.filter_by(name = name, user_id = current_user.id).first()

    if my_list:
        return my_list

    else:
        my_list = TVmovieList(name = name, user_id = current_user.id, titles = [])
        for a_title in title_list:
            my_list.titles.append(a_title)
        db.session.add(my_list)
        db.session.commit()

        return my_list

def get_title_by_id(id):
    title = TVmovieInfo.query.filter_by(id = id).first()
    return title

#routes
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/tvmovie_info', methods=['GET'])
def search():
    form = TvmovieForm(request.args)
    title_object = None
    if request.method == "GET" and form.validate():
        search_imdb = get_title_from_omdb(search = form.search.data)
        find_director = get_or_create_director(name = search_imdb['Director'])
        title = search_imdb['Title']
        rating = search_imdb['imdbRating']
        year = search_imdb['Year']
        plot = search_imdb['Plot']
        director = find_director.id
        my_ranking = int(form.ranking.data)
        new_title = get_or_create_title(title, rating, year, plot, director, my_ranking)
        title_object = TVmovieInfo.query.filter_by(title=title).first()

    errors = [v for v in form.errors.values()]
    if len(errors) > 0:
        flash("There was an error in the form submission! - " + str(errors))
    return render_template('search.html', title_object = title_object, form = form)

@app.route('/all_titles')
def all_titles():
    form = UpdateButtonForm()
    formdel = DeleteButtonForm()
    all_titles = TVmovieInfo.query.all()
    return render_template('all_titles.html', all_titles=all_titles, form=form, formdel=formdel)

@app.route('/all_directors')
def all_directors():
    all_directors = Director.query.all()
    return render_template('all_directors.html', all_directors=all_directors)

@app.route('/create_list',methods=["GET","POST"])
@login_required
def create_list():
    form = ListForm()
    titles = TVmovieInfo.query.all()
    choices = [(t.id, t.title) for t in titles]
    form.movie_picks.choices = choices
    if request.method == 'POST':
        titles = []
        for movie_id in form.movie_picks.data:
            m = get_title_by_id(movie_id)
            titles.append(m)
        print (titles)
        get_or_create_list(db.session, name = form.name.data, current_user = current_user, title_list = titles)
        return redirect(url_for('tvmovie_lists'))
    else:
        return render_template('create_list.html', form = form)

@app.route('/tvmovie_lists', methods=["GET","POST"])
@login_required
def tvmovie_lists():
    each_list = TVmovieList.query.filter_by(user_id = current_user.id).all()
    return render_template('lists.html', lists = each_list)

@app.route('/list/<lst_id>')
def single_list(lst_id):
    id = int(lst_id)
    list = TVmovieList.query.filter_by(id=id).first()
    titles = list.titles.all()
    return render_template('list.html',list=list, titles=titles)

@app.route('/update/<title>', methods = ['GET','POST'])
def update(title):
    form = UpdateRankForm()
    my_title = TVmovieInfo.query.filter_by(title = title).first()
    if form.validate_on_submit():
        new_rank = int(form.update_rank.data)
        my_title.my_ranking = new_rank
        db.session.commit()
        flash("Updated ranking of: " + my_title.title)
        return redirect(url_for('all_titles'))
    return render_template('update.html', form = form, title = title)

@app.route('/delete/<title>', methods=["GET","POST"])
def deleteTitle(title):
    t = TVmovieInfo.query.filter_by(title = title).first()
    db.session.delete(t)
    db.session.commit()
    flash("Successfully deleted {}".format(title))
    return redirect(url_for('all_titles'))


if __name__ == '__main__':
    db.create_all()
    manager.run()

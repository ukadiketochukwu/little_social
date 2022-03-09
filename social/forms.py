from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask import session, abort
from social import app, db
from social.models import User, Post, Follower, Comment, Like
from flask_login import current_user
from flask_mail import Message
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

class AdminModelView(ModelView):
    def is_accessible(self):
        if 'logged_in' in session:
            return True
        else:
            abort(403)


admin = Admin(app, name='Bloggy Admin', template_mode='bootstrap4')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Post, db.session))
admin.add_view(AdminModelView(Comment, db.session))
admin.add_view(AdminModelView(Like, db.session))
admin.add_view(AdminModelView(Follower, db.session))
admin.add_view(AdminModelView(Message, db.session))


class PostForm(FlaskForm):
    post_title = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Title"})
    post_content = TextAreaField(validators=[InputRequired(), Length(
        min=4, max=1000)], render_kw={"placeholder": "Description"})
    submit = SubmitField("Upload Post")


class UpdatePostForm(FlaskForm):
    post_title = StringField("Title", validators=[
        InputRequired(), Length(min=4, max=40)])
    post_content = TextAreaField("Description", validators=[
        InputRequired(), Length(min=4, max=1000)])
    submit = SubmitField("Update Post")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password", validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

    def validate_username(self, username):
        username = User.query.filter_by(username=username.data).first()
        if not username:
            raise ValidationError('Account does not exist.')


class BioForm(FlaskForm):
    bio = TextAreaField('Bio', [Length(min=0, max=1000)])
    submit = SubmitField("Update Bio")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email Address"})
    username = StringField("Username", validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                "That email address belongs to different user. Please choose a different one.")


class UpdateAccount(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Edit Email"})
    username = StringField("Username", validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Edit Username"})
    bio = TextAreaField([Length(min=0, max=1000)], render_kw={
        "placeholder": "Edit Bio"})
    profile_pic = FileField(validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update Account')

    def validate_username(self, username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    "That username already exists. Please choose a different one.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError(
                    "That email address belongs to different user. Please choose a different one.")


class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Send Reset Email")


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "Password (4 minimum)"})


class ChangePasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    current_password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Current Password"})
    new_password = PasswordField(validators=[
        InputRequired(), Length(min=4)], render_kw={"placeholder": "New Password (4 minimum)"})
    submit = SubmitField("Change Password")


class DeleteAccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(
        message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Delete My Account")


class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[InputRequired(), Length(
        min=4)], render_kw={"placeholder": "Enter Comment"})
    submit = SubmitField("Add Comment")


class UserSearchForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=15)], render_kw={"placeholder": "Search For Users"})


class MessageForm(FlaskForm):
    message = StringField(validators=[InputRequired(), Length(
        min=4, max=200)], render_kw={"placeholder": "Send A Message"})

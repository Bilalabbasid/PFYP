import re

from flask_wtf import FlaskForm
from wtforms import (BooleanField, IntegerField, PasswordField, SelectField,
                     StringField, SubmitField, TextAreaField)
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                NumberRange, Optional, Regexp, ValidationError)

USERNAME_RE = r"^[A-Za-z0-9_.-]+$"


def strong_password(form, field):
    value = field.data or ""
    if len(value) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ValidationError("Password must contain both letters and numbers.")


class ScanForm(FlaskForm):
    url = StringField("URL", validators=[DataRequired(message="Please enter a URL."),
                                         Length(max=2048)])
    submit = SubmitField("Analyse")


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(), Length(min=3, max=40),
        Regexp(USERNAME_RE, message="Use letters, numbers, dots, dashes or underscores."),
    ])
    full_name = StringField("Full name", validators=[Optional(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), strong_password])
    confirm = PasswordField("Confirm password", validators=[
        DataRequired(), EqualTo("password", message="Passwords do not match.")])
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    username = StringField("Username or email", validators=[DataRequired(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember me")
    submit = SubmitField("Log in")


class ProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[Optional(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField("Save profile")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), strong_password])
    confirm = PasswordField("Confirm new password", validators=[
        DataRequired(), EqualTo("new_password", message="Passwords do not match.")])
    submit = SubmitField("Change password")


ARTICLE_CATEGORIES = ["Basics", "Techniques", "Detection", "Safe Browsing", "Passwords",
                      "Authentication", "Reporting", "General"]

# Bootstrap Icons names
ARTICLE_ICONS = ["shield-check", "envelope-exclamation", "search", "globe", "key",
                 "phone", "flag", "bug", "lock", "person-badge", "lightbulb"]


class ArticleForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=150)])
    category = SelectField("Category", choices=ARTICLE_CATEGORIES)
    icon = SelectField("Icon", choices=ARTICLE_ICONS)
    summary = StringField("Summary", validators=[DataRequired(), Length(max=300)])
    content = TextAreaField("Content", validators=[DataRequired()],
                            description="Blank line = new paragraph. Lines starting with "
                                        "'- ' become bullet points, '## ' a sub-heading, "
                                        "**text** is bold.")
    position = IntegerField("Display order", default=0,
                            validators=[Optional(), NumberRange(min=0, max=999)])
    published = BooleanField("Published", default=True)
    submit = SubmitField("Save article")

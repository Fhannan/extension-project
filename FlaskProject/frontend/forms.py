from wtforms import Form, validators, PasswordField

class RegisterForInvite(Form):

    password = PasswordField('Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')

class LoginForInvite(Form):

    password = PasswordField('Password', [validators.Required()])



from wtforms import Form, TextField, validators

class CreateAdmin(Form):
    #nameYour is the label of field
    email = TextField('email', [validators.Required()])
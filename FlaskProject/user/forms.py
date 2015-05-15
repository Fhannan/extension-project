from wtforms import Form, TextField, validators

class UpdateProfileForm(Form):
    #nameYour is the label of field
    first_name = TextField('First Name', [validators.Required()])
    last_name = TextField('Last Name', [validators.Required()])

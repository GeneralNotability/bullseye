from django import forms

class WikiForm(forms.Form):
    wikis = forms.MultipleChoiceField(label='Wiki blocks')
    def __init__(self, choices=None, *args, **kwargs):
        super(WikiForm, self).__init__(*args, **kwargs)
        if choices:
            self.fields['wikis'].choices = choices

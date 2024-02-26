from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomeUser, Profile
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions


class CustomUserCreation(UserCreationForm):

    class Meta:
        model = CustomeUser
        fields = [ 'email','username', 'password1', 'password2']


class AuthenticationForm(forms.Form):
    """
    Base class for authenticating users. Extend this to get a form that accepts
    username/password logins.
    """

    email = forms.EmailField()
    password = forms.CharField(
        label=("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class EditProfile(forms.ModelForm):

    class Meta:
        model = Profile
        fields = [ 'user','first_name', 'last_name', 'image', 'phone', 'address']



class ResetPasswordForm(forms.ModelForm): 
    email = forms.EmailField()


class ResetForm(forms.ModelForm):
    password1 = forms.CharField(
        label=("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    password2 = forms.CharField(
        label=("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    def is_valid(self) -> bool:
        password1 = self.cleaned_data['password1']
        password2 = self.cleaned_data['password2']

        if password1 != password2:
            raise forms.ValidationError({"detail": "password dose not confirmed"})

        try:

            validate_password(password1)

        except exceptions.ValidationError as e:

            raise forms.ValidationError({"detail": list(e.messages)})

        return super().is_valid()
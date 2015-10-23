from django import forms
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm
from django.forms.extras.widgets import SelectDateWidget
from django.core.files.images import ImageFile
from django.contrib.auth import get_user_model

from datetime import date
from PIL import Image

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from uaccounts import settings
from uaccounts.models import EmailAddress, UserProfile, Avatar


_e = (
    'Username is required',
    'Username is already in use',
    'Username must consist of '
    '{} characters minimum'.format(settings.USERNAME_MIN_LENGTH),
    'Username must consist of 30 characters maximum',
    'Password is required',
    'You must repeat password',
    'Password must consist of '
    '{} characters minimum'.format(settings.PASSWORD_MIN_LENGTH),
    'The two passwords did not match',
    'Email address is required',
    'Email address is already in use',
    'Invalid email address',
    'Status must consist of '
    '{} characters maximum'.format(settings.STATUS_MAX_LENGTH),
    'Invalid website URL',
    'Invalid date of birth',
    'Invalid avatar',
    'Please either submit an avatar or check "Delete", not both',
)


class LoginForm(forms.Form):
    """User login form."""
    username = forms.CharField(error_messages={'required': _e[0]})
    password = forms.CharField(widget=forms.PasswordInput,
                               error_messages={'required': _e[4]})
    remember = forms.BooleanField(required=False)


class RegistrationForm(UserCreationForm):
    """User registration form."""
    error_messages = {'password_mismatch': _e[7],
                      'email_unique': _e[9],
                      'username_min_length': _e[2]}

    Meta = UserCreationForm.Meta
    Meta.error_messages = {'username': {'unique': _e[1],
                                        'required': _e[0],
                                        'max_length': _e[3]}}

    password1 = forms.CharField(widget=forms.PasswordInput,
                                min_length=settings.PASSWORD_MIN_LENGTH,
                                error_messages={'required': _e[4],
                                                'min_length': _e[6]})
    password2 = forms.CharField(widget=forms.PasswordInput,
                                error_messages={'required': _e[5]})
    email = forms.EmailField(error_messages={'invalid': _e[10],
                                             'required': _e[8]})

    def clean_username(self):
        """Make sure username does not exceed minimum length."""
        code = 'username_min_length'
        username = self.cleaned_data['username']

        if len(username) < settings.USERNAME_MIN_LENGTH:
            raise forms.ValidationError(self.error_messages[code], code)
        return username

    def clean_email(self):
        """Make sure email address is unique."""
        email = self.cleaned_data['email']

        if EmailAddress.objects.filter(address=email, verified=True):
            raise forms.ValidationError(self.error_messages['email_unique'],
                                        'email_unique')
        return email

    def save(self):
        """Set email address, set the user as inactive
        and create a user profile.
        """
        user = super(RegistrationForm, self).save(commit=False)

        user.is_active = False
        user.email = self.cleaned_data['email']
        user.save()

        UserProfile.objects.create(user=user)


class EmailAddressForm(forms.Form):
    """Form with an email address as the only field.
    Used for "forgot password" and "add email".
    """
    email = forms.EmailField(error_messages={'invalid': _e[10],
                                             'required': _e[8]})


class ChangePasswordForm(SetPasswordForm):
    """Change password form. User sets directly the
    new password (twice) without entering the old password."""
    error_messages = {'password_mismatch': _e[7]}

    new_password1 = forms.CharField(widget=forms.PasswordInput,
                                    min_length=settings.PASSWORD_MIN_LENGTH,
                                    error_messages={'required': _e[4],
                                                    'min_length': _e[6]})
    new_password2 = forms.CharField(widget=forms.PasswordInput,
                                    error_messages={'required': _e[5]})


class EditProfileForm(forms.ModelForm):
    """Edit profile form."""
    _year = date.today().year
    YEARS = range(_year - 100, _year + 1)

    class Meta:
        model = UserProfile
        fields = ['gender', 'date_of_birth', 'status', 'website']
        error_messages = {'status': {'max_length': _e[11]},
                          'website': {'invalid': _e[12]}}

    date_of_birth = forms.DateField(required=False,
                                    widget=SelectDateWidget(years=YEARS),
                                    error_messages={'invalid': _e[13]})
    avatar = forms.ImageField(required=False,
                              error_messages={'invalid': _e[14],
                                              'invalid_image': _e[14],
                                              'empty': _e[14],
                                              'contradiction': _e[15]})

    def save(self):
        """Resize and set new avatar, or just delete the old one."""
        profile = super(EditProfileForm, self).save()
        image = self.cleaned_data['avatar']

        if image is not None:
            if image:
                new = Image.open(StringIO(''.join(image.chunks())))
                new.thumbnail((settings.AVATAR_MAX_HEIGHT,
                               settings.AVATAR_MAX_WIDTH), Image.ANTIALIAS)

                result = StringIO()
                new.save(result, new.format)
                avatar, created = Avatar.objects.get_or_create(profile=profile)
                if not created:
                    avatar.image.delete()

                avatar.image.save(image.name, ImageFile(result))
            else:
                try:
                    avatar = profile.avatar
                except Avatar.DoesNotExist:
                    return

                avatar.image.delete()
                avatar.delete()


class EditUserForm(forms.ModelForm):
    """Edit user form."""
    class Meta:
        model = get_user_model()
        fields = ['first_name', 'last_name']

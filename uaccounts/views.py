from django.core.urlresolvers import reverse
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST
from django.http import JsonResponse

from uaccounts.decorators import personal, guest, pending
from uaccounts import forms
from uaccounts.models import EmailAddress
from uaccounts.utils import (profile_emails, verification_mail,
                             verify_token, VerificationError)

from uaccounts.settings import (HOME_URL, ACTIVATION_EXPIRES,
                                CHANGE_PASSWORD_EXPIRES, VERIFICATION_EXPIRES)


@personal
def index(request, template_name='uaccounts/index.html'):
    """User's homepage.

    **context**
      - `primary`: primary email
      - `secondary`: list of verified emails
      - `unverified`: list of unverified emails
      - `count`: total email count
      - `home`: parent url
    """
    context = profile_emails(request.user.profile)
    if HOME_URL != reverse('uaccounts:index'):
        context['home'] = HOME_URL

    return render(request, template_name, context)


@guest
def log_in(request, template_name='uaccounts/login.html',
           pending_template_name='uaccounts/pending.html'):
    """Show the login form, or log the user in.
    If they are already logged in, redirect to index.

    **context**
      - `form`: login form
      - `error`: error message
    """
    form = forms.LoginForm()

    if request.method == 'POST':
        form = forms.LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'],
                                password=form.cleaned_data['password'])

            if user is None:
                return render(request, template_name,
                              {'form': forms.LoginForm(),
                               'error': 'Invalid username or password'})

            if user.is_active:
                login(request, user)
                if not form.cleaned_data['remember']:
                    request.session.set_expiry(0)
                return redirect(request.GET.get('n', HOME_URL))

            if user.profile.pending:
                login(request, user)
                request.session.set_expiry(0)
                return render(request,
                              pending_template_name, {'user': user})

            return render(request, template_name,
                          {'form': forms.LoginForm(),
                           'error': 'Account is inactive'})

    return render(request, template_name, {'form': form})


def log_out(request):
    """Log the user out."""
    logout(request)
    return redirect('uaccounts:login')


@guest
def register(request, template_name='uaccounts/register.html'):
    """Show the registration form, or register a new user.
    If they are logged in, redirect to index.

    **context**
      - `form`: registration form
    """
    form = forms.RegistrationForm()

    if request.method == 'POST':
        form = forms.RegistrationForm(request.POST)
        if form.is_valid():
            logout(request)
            form.save()
            user = authenticate(username=form.cleaned_data['username'],
                                password=form.cleaned_data['password1'])
            login(request, user)
            request.session.set_expiry(0)
            return redirect('uaccounts:send')

    return render(request, template_name, {'form': form})


@pending
def send(request):
    """Create activation code, send account activation email
    and show the pending page.
    """
    verification_mail(request, request.user.profile.email,
                      'account activation', 'activation', 'activate')
    return redirect('uaccounts:login')


@pending
def activate(request, token, template_name='uaccounts/activated.html'):
    """Try to activate account using given token."""
    try:
        verification = verify_token(token, ACTIVATION_EXPIRES)
    except VerificationError:
        return redirect('uaccounts:login')

    if verification.email.profile != request.user.profile:
        return redirect('uaccounts:login')

    verification.email.profile.user.is_active = True
    verification.email.profile.user.save()

    verification.email.profile.pending = False
    verification.email.profile.save()

    verification.email.verified = True
    verification.email.save()

    verification.delete()
    logout(request)
    return render(request, template_name)


@guest
def forgot(request, template_name='uaccounts/forgot.html',
           sent_template_name='uaccounts/forgotsent.html'):
    """Create a "forgot password" verification code and
    send the respective email, or just show the "forgot password" page.

    **context**
      - `email`: email address the mail was sent to
      - `form`: "forgot password" form
      - `error`: error message
    """
    form = forms.EmailAddressForm()

    if request.method == 'POST':
        form = forms.EmailAddressForm(request.POST)
        if form.is_valid():
            address = form.cleaned_data['email']
            try:
                email = EmailAddress.objects.get(verified=True,
                                                 address=address)
            except EmailAddress.DoesNotExist:
                return render(request, template_name,
                              {'form': forms.EmailAddressForm(),
                               'error': True})

            verification_mail(request, email,
                              'change password', 'forgot', 'change')
            return render(request,
                          sent_template_name, {'email': email})

    return render(request, template_name, {'form': form})


@guest
def change(request, token,
           template_name='uaccounts/change.html',
           changed_template_name='uaccounts/changed.html'):
    """If confirmation code is valid, show the password change form
    or try to change the password.

    **context**
      - `form`: "change password" form
    """
    try:
        verification = verify_token(token, CHANGE_PASSWORD_EXPIRES)
    except VerificationError:
        return redirect('uaccounts:login')

    if not verification.email.verified:
        return redirect('uaccounts:login')

    user = verification.email.profile.user
    form = forms.ChangePasswordForm(user)

    if request.method == 'POST':
        form = forms.ChangePasswordForm(user, request.POST)
        if form.is_valid():
            form.save()
            verification.delete()
            return render(request, changed_template_name)

    return render(request, template_name, {'form': form})


@personal
def edit(request, template_name='uaccounts/edit.html'):
    """Show "edit profile" page or process the profile editing.

    **context**
      - `form`: "edit profile" form
    """
    profile_form = forms.EditProfileForm(instance=request.user.profile)
    user_form = forms.EditUserForm(instance=request.user)

    if request.method == 'POST':
        profile_form = forms.EditProfileForm(request.POST, request.FILES,
                                             instance=request.user.profile)
        user_form = forms.EditUserForm(request.POST, instance=request.user)
        if profile_form.is_valid():
            profile_form.save()
            user_form.save()
            return redirect('uaccounts:login')

    context = {'form': profile_form}
    context.update(profile_emails(request.user.profile, get_unverified=True))

    return render(request, template_name, context)


@personal
def verify(request, token, template_name='uaccounts/verified.html'):
    """Try to verify email address using given token."""
    try:
        verification = verify_token(token, VERIFICATION_EXPIRES)
    except VerificationError:
        return redirect('uaccounts:index')

    if verification.email.profile != request.user.profile:
        return redirect('uaccounts:index')

    verification.email.verified = True
    verification.email.save()

    verification.delete()
    return render(request, template_name)


@require_POST
@personal
def primary_email(request):
    """Set an email address as user's primary. Used through AJAX.

    POST data: `id`
    """
    try:
        email = request.user.profile.emails.get(pk=request.POST.get('id'))
    except (EmailAddress.DoesNotExist, ValueError):
        return JsonResponse({'success': False,
                             'error': 'You do not have such an '
                                      'email address'})
    if email.primary:
        return JsonResponse({'success': False,
                             'error': 'Email address is already primary'})
    if not email.verified:
        return JsonResponse({'success': False,
                             'error': 'Cannot set as primary '
                                      'an unverified email address'})

    email.set_primary()
    return JsonResponse({'success': True})


@require_POST
@personal
def remove_email(request):
    """Remove an email address. Used through AJAX.

    POST data: `id`
    """
    try:
        email = request.user.profile.emails.get(pk=request.POST.get('id'))
    except (EmailAddress.DoesNotExist, ValueError):
        return JsonResponse({'success': False,
                             'error': 'You do not have such an '
                                      'email address'})
    if email.primary:
        return JsonResponse({'success': False,
                             'error': 'You cannot delete your primary '
                                      'email address'})

    email.delete()
    return JsonResponse({'success': True})


@require_POST
@personal
def verify_email(request):
    """Send email address verification mail. Used through AJAX.

    POST data: `id`
    """
    try:
        email = request.user.profile.emails.get(pk=request.POST.get('id'))
    except (EmailAddress.DoesNotExist, ValueError):
        return JsonResponse({'success': False,
                             'error': 'You do not have such an '
                                      'email address'})
    if email.verified:
        return JsonResponse({'success': False,
                             'error': 'Email address is already verified'})

    verification_mail(request, email,
                      'verify email address', 'verify', 'verify')
    return JsonResponse({'success': True})


@require_POST
@personal
def add_email(request):
    """Add new email address. Used through AJAX.

    POST data: `email`
    """
    form = forms.EmailAddressForm(request.POST)

    if form.is_valid():
        address = form.cleaned_data['email']
        if EmailAddress.objects.filter(address=address, verified=True):
            return JsonResponse({'success': False,
                                 'error': 'Email address is already in use'})

        email = EmailAddress.objects.create(address=address,
                                            profile=request.user.profile)
        return JsonResponse({'success': True, 'id': email.pk})

    return JsonResponse({'success': False, 'error': form.errors['email'][0]})

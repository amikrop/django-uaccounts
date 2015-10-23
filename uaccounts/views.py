from django.views.generic.base import TemplateView
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


class IndexView(TemplateView):
    """User's homepage."""
    template_name = 'uaccounts/index.html'

    def get_context_data(self, **kwargs):
        """Add user's emails to the context.
        If home URL is not this app's index, show a link to it.
        """
        context = super(IndexView, self).get_context_data(**kwargs)

        context.update(profile_emails(self.request.user.profile))
        if HOME_URL != reverse('uaccounts:index'):
            context['home'] = HOME_URL

        return context


index = personal(IndexView.as_view())


@guest
def log_in(request):
    """Show the login form, or log the user in.
    If they are already logged in, redirect to index.
    """
    form = forms.LoginForm()

    if request.method == 'POST':
        form = forms.LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'],
                                password=form.cleaned_data['password'])

            if user is None:
                return render(request, 'uaccounts/login.html',
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
                              'uaccounts/pending.html', {'user': user})

            return render(request, 'uaccounts/login.html',
                          {'form': forms.LoginForm(),
                           'error': 'Account is inactive'})

    return render(request, 'uaccounts/login.html', {'form': form})


def log_out(request):
    """Log the user out."""
    logout(request)
    return redirect('uaccounts:login')


@guest
def register(request):
    """Show the registration form, or register a new user.
    If they are logged in, redirect to index.
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

    return render(request, 'uaccounts/register.html', {'form': form})


@pending
def send(request):
    """Create activation code, send account activation email
    and show the pending page.
    """
    verification_mail(request, request.user.profile.email,
                      'account activation', 'activation', 'activate')
    return redirect('uaccounts:login')


@pending
def activate(request, token):
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
    return render(request, 'uaccounts/activated.html')


@guest
def forgot(request):
    """Create a "forgot password" verification code and
    send the respective email, or just show the "forgot password" page.
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
                return render(request, 'uaccounts/forgot.html',
                              {'form': forms.EmailAddressForm(),
                               'error': True})

            verification_mail(request, email,
                              'change password', 'forgot', 'change')
            return render(request,
                          'uaccounts/forgotsent.html', {'email': email})

    return render(request, 'uaccounts/forgot.html', {'form': form})


@guest
def change(request, token):
    """If confirmation code is valid, show the password change form
    or try to change the password.
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
            return render(request, 'uaccounts/changed.html')

    return render(request, 'uaccounts/change.html', {'form': form})


@personal
def edit(request):
    """Show "edit profile" page or process the profile editing."""
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

    return render(request, 'uaccounts/edit.html', context)


@personal
def verify(request, token):
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
    return render(request, 'uaccounts/verified.html')


@require_POST
@personal
def primary_email(request):
    """Set an email address as user's primary. Used through AJAX."""
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
    """Remove an email address. Used through AJAX."""
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
    """Send email address verification mail. Used through AJAX."""
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
    """Add new email address. Used through AJAX."""
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

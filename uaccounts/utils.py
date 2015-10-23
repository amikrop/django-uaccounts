from django.contrib.sites.shortcuts import get_current_site
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.conf import settings
from django.core.signing import (TimestampSigner,
                                 BadSignature, SignatureExpired)

from uuid import UUID

from uaccounts.models import VerificationCode


def profile_emails(profile, get_unverified=False):
    """Return a dict of users profile's emails,
    divided in primary, rest and optionally unverified.
    Also pass their total count.
    """
    emails = profile.emails.filter(verified=True).order_by('-primary')
    result = {'primary': emails[0], 'secondary': emails[1:]}
    count = len(emails)

    if get_unverified:
        result['unverified'] = profile.emails.filter(verified=False)
        count += len(result['unverified'])

    result['count'] = count
    return result


class VerificationError(Exception):
    """Failed to verify token."""


def verification_mail(request, email, subject, template, action):
    """Delete email's verification code if it exists and
    then create a new one. Then construct and send the
    respective email.
    """
    try:
        email.verification.delete()
    except VerificationCode.DoesNotExist:
        pass
    VerificationCode.objects.create(email=email)
    email.refresh_from_db()

    site = get_current_site(request)
    url = 'http://{}{}'.format(site.domain,
                               reverse('uaccounts:' + action,
                                       args=[email.verification.url]))

    message = render_to_string('uaccounts/{}.txt'.format(template),
                               {'name': site.name, 'url': url})

    send_mail('{} {}'.format(site.name, subject),
              strip_tags(message),
              settings.DEFAULT_FROM_EMAIL,
              [email.address],
              html_message=message)


def verify_token(token, max_age):
    """Try to verify token and return the respective
    VerificationCode instance. Raise VerificationError on failure.
    """
    string = '{}:{}'.format(token[:32], token[32:])
    try:
        token = TimestampSigner().unsign(string, max_age)
    except (BadSignature, SignatureExpired):
        raise VerificationError

    try:
        return VerificationCode.objects.get(token=UUID(token))
    except VerificationCode.DoesNotExist:
        raise VerificationError

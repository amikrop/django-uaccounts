from django.db import models
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.core.signing import TimestampSigner

from uuid import uuid4

from uaccounts.settings import STATUS_MAX_LENGTH, AVATAR_DIR


class UserProfile(models.Model):
    """Contains user details and information."""
    GENDER_UNSPECIFIED = '-'
    GENDER_MALE = 'm'
    GENDER_FEMALE = 'f'
    GENDERS = (
        (GENDER_UNSPECIFIED, _('unspecified')),
        (GENDER_MALE, _('male')),
        (GENDER_FEMALE, _('female')),
    )
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                related_name='profile',
                                verbose_name=_('user'))

    gender = models.CharField(max_length=1, choices=GENDERS,
                              default=GENDER_UNSPECIFIED,
                              verbose_name=_('gender'))

    date_of_birth = models.DateField(null=True, blank=True,
                                     verbose_name=_('date of birth'))

    status = models.CharField(max_length=STATUS_MAX_LENGTH,
                              blank=True, verbose_name=_('status'))

    website = models.URLField(blank=True, verbose_name=_('website'))

    pending = models.BooleanField(default=True,
                                  verbose_name=_('pending for activation'))

    updated = models.DateTimeField(auto_now=True,
                                   verbose_name=_('last updated'))

    class Meta:
        verbose_name = _('user profile')
        verbose_name_plural = _('user profiles')

    def __unicode__(self):
        return self.user.username

    @property
    def email(self):
        """Primary email, an EmailAddress instance,
        or None if none exist.
        """
        results = self.emails.order_by('-primary')
        if results:
            return results[0]

    def save(self, *args, **kwargs):
        """Add the existing email address."""
        new = self.pk is None
        super(UserProfile, self).save(*args, **kwargs)
        if new and self.user.email:
            self.emails.create(address=self.user.email,
                               primary=True, verified=True)


class EmailAddress(models.Model):
    """Email address belonging to a user profile."""
    profile = models.ForeignKey('UserProfile', related_name='emails',
                                verbose_name=_('profile'))
    address = models.EmailField(_('address'))
    primary = models.BooleanField(default=False, verbose_name=_('primary'))
    verified = models.BooleanField(default=False, verbose_name=_('verified'))
    modified = models.DateTimeField(auto_now=True,
                                    verbose_name=_('last modified'))

    class Meta:
        verbose_name = _('email address')
        verbose_name_plural = _('email addresses')
        ordering = ['modified']

    def __unicode__(self):
        return self.address

    def set_primary(self):
        """Set this as primary, after unsetting all the rest
        the user has.
        """
        self.profile.emails.update(primary=False)
        self.primary = True
        self.save()

        self.profile.user.email = self.address
        self.profile.user.save()


class VerificationCode(models.Model):
    """Verification code of an email address, also used
    to activate user account and to change forgotten password.
    """
    email = models.OneToOneField('EmailAddress', related_name='verification',
                                 verbose_name=_('email'))
    token = models.UUIDField(default=uuid4,
                             unique=True, verbose_name=_('token'))

    class Meta:
        verbose_name = _('verification code')
        verbose_name_plural = _('verification codes')

    def __unicode__(self):
        return self.token.hex

    @property
    def url(self):
        """String to be part of the verification URL."""
        string = TimestampSigner().sign(self.token.hex)
        return string[:32] + string[33:]


class Avatar(models.Model):
    """Profile avatar, stores height and width."""
    profile = models.OneToOneField('UserProfile', related_name='avatar',
                                   verbose_name=_('profile'))
    image = models.ImageField(upload_to=AVATAR_DIR, null=True,
                              blank=True, height_field='height',
                              width_field='width', verbose_name=_('image'))
    height = models.PositiveSmallIntegerField(null=True, blank=True,
                                              verbose_name=_('height'))
    width = models.PositiveSmallIntegerField(null=True, blank=True,
                                             verbose_name=_('width'))

    class Meta:
        verbose_name = _('avatar')
        verbose_name_plural = _('avatars')

    def __unicode__(self):
        return self.image.name

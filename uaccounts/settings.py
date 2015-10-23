from django.conf import settings
from django.core.urlresolvers import reverse_lazy


HOME_URL = getattr(settings,
                   'UACCOUNTS_HOME_URL', reverse_lazy('uaccounts:index'))

USERNAME_MIN_LENGTH = getattr(settings, 'UACCOUNTS_USERNAME_MIN_LENGTH', 4)

PASSWORD_MIN_LENGTH = getattr(settings, 'UACCOUNTS_PASSWORD_MIN_LENGTH', 6)

STATUS_MAX_LENGTH = getattr(settings, 'UACCOUNTS_STATUS_MAX_LENGTH', 200)

ACTIVATION_EXPIRES = getattr(settings,
                             'UACCOUNTS_ACTIVATION_EXPIRES', 24 * 60 * 60)

CHANGE_PASSWORD_EXPIRES = getattr(settings,
                                  'UACCOUNTS_CHANGE_PASSWORD_EXPIRES',
                                  60 * 60)

VERIFICATION_EXPIRES = getattr(settings,
                               'UACCOUNTS_VERIFICATION_EXPIRES', None)

AVATAR_DIR = getattr(settings, 'UACCOUNTS_AVATAR_DIR', 'avatars/')

AVATAR_MAX_HEIGHT = getattr(settings, 'UACCOUNTS_AVATAR_MAX_HEIGHT', 200)

AVATAR_MAX_WIDTH = getattr(settings, 'UACCOUNTS_AVATAR_MAX_WIDTH', 200)

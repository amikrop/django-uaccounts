django-uaccounts
================

Pluggable user accounts and profiles
-------------------------------------

**django-uaccounts** is a pluggable Django app that provides
user registration, login/logout and a "forgot password" feature.
Email verification is required for account activation and resetting
password. The app also supports simple user profiles, with multiple
email addresses that can be verified as well.

Installation
------------

- Download and install from PyPI:

.. code::

    pip install django-uaccounts

- Add it to your *INSTALLED_APPS*, as well as *'django.contrib.sites'*:

.. code:: python

    INSTALLED_APPS = (
        ...
        'django.contrib.sites',
        ...
        'uaccounts',
        ...
    )

- Make sure you have a *django.contrib.sites.models.Site* instance saved in your database as **django-uaccounts** needs it to get the name and the domain of your site to include them in the verification emails.

- Configure the email settings of your project as they are needed for sending the verification emails.

- Include the urlconf of the app in your project's urls.py:

.. code:: python

    from django.conf.urls import url, include

    urlpatterns = [
        ...
        url(r'accounts/', include('uaccounts.urls', namespace='uaccounts')),
        ...
    ]

Of course, you can put it under any url you want,
like *r''* or *r'^mysite/myaccounts/'*.

Usage
-----

**django-uaccounts** can be a very simple standalone app, but its main
purpose is to offer user account capabilities to your project,
complementing your other apps. To test its usage on its own, you should
be ready to go by now. However you probably want to let it know
its "parent url". This is a url to redirect to after a
successful login, and provide a link for in the "profile" page, so the
user can return to the main aspect of your website. This url can be set
through the *UACCOUNTS_HOME_URL* setting.

Settings
--------

All of the app settings are optional but you may want to modify them
to customize to your needs, and most probably *UACCOUNTS_HOME_URL* to
connect this app with the rest of your project.

- **UACCOUNTS_HOME_URL**: The "parent url". Can be an *str* or a call to *django.core.urlresolvers.reverse_lazy*.

    Default: *django.core.urlresolvers.reverse_lazy('uaccounts:index')*

- **UACCOUNTS_USERNAME_MIN_LENGTH**: Minimum allowed characters for username.

    Default: *4*

- **UACCOUNTS_PASSWORD_MIN_LENGTH**: Minimum allowed characters for password.

    Default: *6*

- **UACCOUNTS_STATUS_MAX_LENGTH**: Maximum allowed characters for status.

    Default: *200*

- **UACCOUNTS_ACTIVATION_EXPIRES**: Expiration time of an account activation request, in seconds. Can be an *int* or *None* for limitless time.

    Default: *24 \* 60 \* 60*

- **UACCOUNTS_CHANGE_PASSWORD_EXPIRES**: Expiration time of a "forgot password" request, in seconds. Can be an *int* or *None* for limitless time.

    Default: *60 \* 60*

- **UACCOUNTS_VERIFICATION_EXPIRES**: Expiration time of an email verification request, in seconds. Can be an *int* or *None* for limitless time.

    Default: *None*

- **UACCOUNTS_AVATAR_DIR**: Directory for uploading user avatars. It gets appended to your *MEDIA_ROOT*.

    Default: *'avatars/'*

- **UACCOUNTS_AVATAR_MAX_HEIGHT**: Maximum allowed height for user avatars, in pixels. Avatars get resized (kept in scale) if this is exceeded.

    Default: *200*

- **UACCOUNTS_AVATAR_MAX_WIDTH**: Maximum allowed width for user avatars, in pixels. Avatars get resized (kept in scale) if this is exceeded.

    Default: *200*

License
-------

BSD

Author
------

Aristotelis Mikropoulos *<amikrop@gmail.com>*

from django.contrib.auth.decorators import user_passes_test
from django.core.urlresolvers import reverse_lazy
from django.utils.decorators import available_attrs
from django.shortcuts import redirect, render

from functools import wraps


def personal(view):
    """Ensure user is logged in and active."""
    def test(user):
        return user.is_authenticated() and user.is_active

    decorator = user_passes_test(test, reverse_lazy('uaccounts:login'), 'n')
    return decorator(view)


def pending(view):
    """Ensure user is logged in and pending."""
    def test(user):
        return user.is_authenticated() and user.profile.pending

    decorator = user_passes_test(test, reverse_lazy('uaccounts:login'), None)
    return decorator(view)


def guest(view):
    """Ensure user is not logged in."""
    @wraps(view, assigned=available_attrs(view))
    def wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated():
            if request.user.is_active:
                return redirect('uaccounts:index')

            return render(request,
                          'uaccounts/pending.html', {'user': request.user})
        return view(request, *args, **kwargs)

    return wrapped_view

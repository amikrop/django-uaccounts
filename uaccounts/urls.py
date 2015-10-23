from django.conf.urls import url

from uaccounts import views


urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^profile/$', views.index, name='profile'),
    url(r'^login/$', views.log_in, name='login'),
    url(r'^logout/$', views.log_out, name='logout'),
    url(r'^register/$', views.register, name='register'),
    url(r'^send/$', views.send, name='send'),
    url(r'^activate/(?P<token>[^/]+)/$', views.activate, name='activate'),
    url(r'^forgot/$', views.forgot, name='forgot'),
    url(r'^change/(?P<token>[^/]+)/$', views.change, name='change'),
    url(r'^edit/$', views.edit, name='edit'),
    url(r'^verify/(?P<token>[^/]+)/$', views.verify, name='verify'),
    url(r'^primaryemail/$', views.primary_email, name='primary-email'),
    url(r'^removeemail/$', views.remove_email, name='remove-email'),
    url(r'^verifyemail/$', views.verify_email, name='verify-email'),
    url(r'^addemail/$', views.add_email, name='add-email'),
]

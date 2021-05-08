"""DjOps URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,re_path

urlpatterns = [
    path('admin/', admin.site.urls),
]

from management import views as mv
from django.conf.urls import handler404, handler500


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', mv.login),
    path('logout/', mv.logout),
    path('', mv.index),
    path('allinfo/', mv.allinfo),
    path('groupinfo/', mv.groupinfo),
    path('resinfo/', mv.resinfo),
    path('hostupdate/', mv.hostupdate),
    path('hostdelete/', mv.hostdelete),
    path('groupupdate/', mv.groupupdate),
    path('groupdelete/', mv.groupdelete),
    path('scan/', mv.scan),
    path('add/', mv.add_test_host),
    path('collect/', mv.collect_ip_mac),
    path('shell/', mv.run_shell),
    path('script/', mv.run_script),

    #path('api/hosts/', mv.HostView.as_view(actions={'get': 'retrieve', 'post': 'create'})),

    path('api/hosts/', mv.HostView.as_view(actions={'get': 'list','post':'create'})),
    re_path('api/hosts/(?P<pk>\d+)',
            mv.HostView.as_view(actions={'get': 'retrieve','put':'update'})),

]
handler404 = mv.page_not_found
from django.urls import path

from . import views

app_name = "detection"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("incidents/", views.incident_list, name="incident_list"),
    path("incidents/<int:pk>/", views.incident_detail, name="incident_detail"),
    path("hosts/", views.host_list, name="host_list"),
    path("hosts/<int:pk>/", views.host_detail, name="host_detail"),
    path("pools/", views.pool_list, name="pool_list"),
]

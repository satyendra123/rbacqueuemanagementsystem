from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('account.urls')),  # Existing account URLs
    path('api/', include('doctors.urls')),  # Added doctors URLs
]

from django.urls import path
from .views import (
    create_department, update_department, delete_department, get_all_departments, get_department_by_id,
    create_doctor, delete_doctor, get_all_doctors, get_doctor_by_id
)

urlpatterns = [
    # Department Endpoints
    path('create/department/', create_department, name='create_department'),
    path('update/department/<int:department_id>/', update_department, name='update_department'),
    path('delete/department/<int:department_id>/', delete_department, name='delete_department'),
    path('get/department/all/', get_all_departments, name='get_all_departments'),
    path('get/department/<int:department_id>/', get_department_by_id, name='get_department_by_id'),

    # Doctor Endpoints
    path('create/doctor/', create_doctor, name='create_doctor'),
    path('delete/doctor/<int:doctor_id>/', delete_doctor, name='delete_doctor'),
    path('get/doctor/all/', get_all_doctors, name='get_all_doctors'),
    path('get/doctor/<int:doctor_id>/', get_doctor_by_id, name='get_doctor_by_id'),
]

from django.shortcuts import render
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from account.middleware import admin_required, admin_permission
from .models import Department, Doctor
from .serializers import DepartmentSerializer, DoctorSerializer

@csrf_exempt
@admin_permission("create_departments")
def create_department(request):
    """Create a new department"""
    try:
        body = json.loads(request.body)
        department_name = body.get('name')

        if not department_name:
            return JsonResponse({"detail": "Department name is required"}, status=400)

        serializer = DepartmentSerializer(data=body)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)


@csrf_exempt
@admin_required
@admin_permission("update_departments")
def update_department(request, department_id):
    """Update an existing department"""
    try:
        department = Department.objects.get(id=department_id)
    except Department.DoesNotExist:
        return JsonResponse({"detail": "Department not found"}, status=404)

    try:
        body = json.loads(request.body)
        serializer = DepartmentSerializer(department, data=body, partial=True)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=200)
        return JsonResponse(serializer.errors, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)


@csrf_exempt
@admin_required
@admin_permission("delete_departments")
def delete_department(request, department_id):
    """Delete a department"""
    try:
        department = Department.objects.get(id=department_id)
        department.delete()
        return JsonResponse({"detail": "Department deleted successfully"}, status=200)
    except Department.DoesNotExist:
        return JsonResponse({"detail": "Department not found"}, status=404)


@csrf_exempt
@admin_permission("view_departments")
def get_all_departments(request):
    """Retrieve all departments"""
    departments = Department.objects.all()
    serializer = DepartmentSerializer(departments, many=True)
    return JsonResponse(serializer.data, safe=False, status=200)


@csrf_exempt
@admin_required
@admin_permission("view_departments")
def get_department_by_id(request, department_id):
    """Retrieve a department by ID"""
    try:
        department = Department.objects.get(id=department_id)
        serializer = DepartmentSerializer(department)
        return JsonResponse(serializer.data, status=200)
    except Department.DoesNotExist:
        return JsonResponse({"detail": "Department not found"}, status=404)


# ---------------------- Doctor APIs ----------------------

@csrf_exempt
@admin_required
@admin_permission("create_doctors")
def create_doctor(request):
    """Create a new doctor (Ensures department ID is provided)"""
    try:
        body = json.loads(request.body)
        department_id = body.get('department')

        if not department_id:
            return JsonResponse({"error": "Department ID is required."}, status=400)

        try:
            department = Department.objects.get(id=department_id)
        except Department.DoesNotExist:
            return JsonResponse({"error": "Invalid department ID."}, status=400)

        serializer = DoctorSerializer(data=body)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        return JsonResponse(serializer.errors, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)


@csrf_exempt
@admin_required
@admin_permission("delete_doctors")
def delete_doctor(request, doctor_id):
    """Delete a doctor"""
    try:
        doctor = Doctor.objects.get(id=doctor_id)
        doctor.delete()
        return JsonResponse({"detail": "Doctor deleted successfully"}, status=200)
    except Doctor.DoesNotExist:
        return JsonResponse({"detail": "Doctor not found"}, status=404)


@csrf_exempt
@admin_required
@admin_permission("view_doctors")
def get_all_doctors(request):
    """Retrieve all doctors"""
    doctors = Doctor.objects.all()
    serializer = DoctorSerializer(doctors, many=True)
    return JsonResponse(serializer.data, safe=False, status=200)


@csrf_exempt
@admin_required
@admin_permission("view_doctors")
def get_doctor_by_id(request, doctor_id):
    """Retrieve a doctor by ID"""
    try:
        doctor = Doctor.objects.get(id=doctor_id)
        serializer = DoctorSerializer(doctor)
        return JsonResponse(serializer.data, status=200)
    except Doctor.DoesNotExist:
        return JsonResponse({"detail": "Doctor not found"}, status=404)

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import Role, Permission, UserRole, RolePermission, CustomUser
from .serializers import CustomUserSerializer, RoleSerializer, PermissionSerializer,RolePermissionSerializer,UserRoleSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
import bcrypt
from django.http import JsonResponse
import json
from account.middleware import admin_required
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.shortcuts import get_object_or_404
from .middleware import admin_required, admin_permission 

@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    name = request.data.get('name')

    if CustomUser.objects.filter(username=username).exists():
        return Response({"detail": "Username already exists"}, status=status.HTTP_400_BAD_REQUEST)
    if CustomUser.objects.filter(email=email).exists():
        return Response({"detail": "Email already exists"}, status=status.HTTP_400_BAD_REQUEST)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    user = CustomUser.objects.create(
        username=username,
        email=email,
        name=name,
        password=hashed_password.decode('utf-8')  # Store the hashed password
    )
    user.save()

    return Response({"detail": "User registered successfully"}, status=status.HTTP_201_CREATED)

# Login API
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email = request.data.get('username')
    password = request.data.get('password')
    
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

    # Manually checking the password with bcrypt
    if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        role = Role.objects.filter(id=user.id).first()

        if role:
            refresh = RefreshToken.for_user(user)
            refresh['role_name'] = role.name
            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'role': role.name
            })
        else:
            return Response({"detail": "User does not have an associated role"}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
def logout(request):
    token = request.headers.get('Authorization')
    if token is None:
        return JsonResponse({"detail": "Authorization token missing"}, status=401)

    try:
        token = token.split(' ')[1]
        refresh_token = RefreshToken(token)
        refresh_token.blacklist()
        return JsonResponse({"detail": "Successfully logged out and token blacklisted"}, status=200)

    except Exception as e:
        return JsonResponse({"detail": f"An error occurred: {str(e)}"}, status=500)
    
# code for the Role table
@csrf_exempt
@admin_required
@admin_permission("create_role")
def create_role(request):
    """
    View to create a new role. Only accessible by users with an 'admin' role.
    """
    try:
        body = json.loads(request.body)
        role_name = body.get('name')

        if not role_name:
            return JsonResponse({"detail": "Role name is required"}, status=400)

        # Create the role in the database
        role, created = Role.objects.get_or_create(name=role_name)

        if created:
            return JsonResponse({"detail": f"Role '{role_name}' created successfully"}, status=201)
        else:
            return JsonResponse({"detail": f"Role '{role_name}' already exists"}, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=500)
    
# Update a Role

@csrf_exempt
def update_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return Response({'detail': 'Role not found'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'PUT':
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Delete a Role
@csrf_exempt  # Exempt CSRF for DELETE requests if necessary
def delete_role(request, pk):
    try:
        role = Role.objects.get(pk=pk)
    except Role.DoesNotExist:
        return JsonResponse({'detail': 'Role not found'}, status=404)

    role.delete()
    return JsonResponse({'detail': 'Role deleted successfully'}, status=204)
    

# Create a Permission

@csrf_exempt
def create_permission(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # Parse JSON manually
            serializer = PermissionSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=201)  # Return JSON response
            return JsonResponse(serializer.errors, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"detail": "Invalid JSON format"}, status=400)


# Update a Permission
@csrf_exempt
def update_permission(request, pk):
    try:
        permission = Permission.objects.get(pk=pk)
    except Permission.DoesNotExist:
        return JsonResponse({"error": "Permission not found"}, status=404)

    if request.method == 'PUT':
        try:
            data = json.loads(request.body.decode('utf-8'))  # Manually parse JSON
            serializer = PermissionSerializer(permission, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse(serializer.data, status=200)
            return JsonResponse(serializer.errors, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)


# Delete a Permission
@csrf_exempt
def delete_permission(request, pk):
    try:
        permission = Permission.objects.get(pk=pk)
    except Permission.DoesNotExist:
        return JsonResponse({"error": "Permission not found"}, status=404)

    if request.method == 'DELETE':
        permission.delete()
        return JsonResponse({"message": "Permission deleted successfully"}, status=200)


# Assign Role to User
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def assign_role_to_user(request):
    try:
        data = json.loads(request.body)
        user_id = data.get('user_id')
        role_id = data.get('role_id')

        user = get_object_or_404(CustomUser, id=user_id)
        role = get_object_or_404(Role, id=role_id)

        user_role, created = UserRole.objects.get_or_create(user=user, role=role)
        
        if created:
            return JsonResponse({"detail": "Role assigned to user successfully"}, status=201)
        else:
            return JsonResponse({"detail": "User already has this role"}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=500)

# Assign Permission to Role
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def assign_permission_to_role(request):
    try:
        data = json.loads(request.body)
        role_id = data.get('role_id')
        permission_id = data.get('permission_id')

        role = get_object_or_404(Role, id=role_id)
        permission = get_object_or_404(Permission, id=permission_id)

        role_permission, created = RolePermission.objects.get_or_create(role=role, permission=permission)
        
        if created:
            return JsonResponse({"detail": "Permission assigned to role successfully"}, status=201)
        else:
            return JsonResponse({"detail": "Role already has this permission"}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({"detail": "Invalid JSON format"}, status=400)
    except Exception as e:
        return JsonResponse({"detail": str(e)}, status=500)

# Retrieve User Roles
@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_roles(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    roles = user.roles.all()
    role_list = [role.role.name for role in roles]
    return JsonResponse({"roles": role_list}, status=200)

# Retrieve Role Permissions
@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def get_role_permissions(request, role_id):
    role = get_object_or_404(Role, id=role_id)
    permissions = role.permissions.all()
    permission_list = [perm.permission.name for perm in permissions]
    return JsonResponse({"permissions": permission_list}, status=200)

@csrf_exempt
@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_permissions(request, user_id):
    try:
        user_roles = UserRole.objects.filter(user_id=user_id).select_related('role')
        permissions = RolePermission.objects.filter(role__in=[role.role for role in user_roles])
        permission_list = [permission.permission.permission_name for permission in permissions]  # Fixed line
        
        return JsonResponse({"permissions": permission_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
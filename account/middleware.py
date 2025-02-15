from functools import wraps
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import CustomUser, UserRole, Permission, RolePermission
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed

def admin_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        token = request.headers.get('Authorization')
        if token is None:
            return JsonResponse({"detail": "Authorization token missing"}, status=401)

        try:
            token = token.split(' ')[1]
            jwt_authentication = JWTAuthentication()
            validated_token = jwt_authentication.get_validated_token(token)
            user_id = validated_token["user_id"]
            user = CustomUser.objects.get(id=user_id)
            request.user = user  # Set the user in the request

        except Exception as e:
            return JsonResponse({"detail": "Authorization error: " + str(e)}, status=401)

        return view_func(request, *args, **kwargs)

    return _wrapped_view

def admin_permission(permission_name):
    """
    Decorator to check if the authenticated user has the required permission.
    Uses JWT authentication to validate the token and extract user details.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Get token from Authorization header
            token = request.headers.get("Authorization")
            if not token:
                return JsonResponse({"detail": "Authorization token missing"}, status=401)

            try:

                token = token.split(" ")[1]
                jwt_authentication = JWTAuthentication()
                validated_token = jwt_authentication.get_validated_token(token)
                user_id = validated_token["user_id"]

                user = CustomUser.objects.get(id=user_id)
                request.user = user
            except (IndexError, AuthenticationFailed, CustomUser.DoesNotExist):
                return JsonResponse({"detail": "Invalid or expired token"}, status=401)

            user_roles = UserRole.objects.filter(user=user).values_list("role", flat=True)
            has_permission = RolePermission.objects.filter(
                role__in=user_roles, permission__permission_key=permission_name
            ).exists()

            if not has_permission:
                return JsonResponse(
                    {"detail": f"User does not have '{permission_name}' permission"},
                    status=403,
                )

            return view_func(request, *args, **kwargs)

        return _wrapped_view

    return decorator

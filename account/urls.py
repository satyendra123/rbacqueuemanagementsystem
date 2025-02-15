from django.urls import path
from .views import login,logout, create_role, update_role, delete_role,create_permission, update_permission, delete_permission,assign_role_to_user,assign_permission_to_role,get_user_roles, get_user_permissions
from account.middleware import admin_required
urlpatterns = [
    # Authentication
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),

    # Role management (protected by AdminAuthenticationMiddleware)
    path('role/create/', create_role, name='create_role'),
    path('role/<int:pk>/update/', admin_required(update_role), name='update_role'),
    path('role/<int:pk>/delete/', admin_required(delete_role), name='delete_role'),

    # Permission management (protected by AdminAuthenticationMiddleware)
    path('permission/create/', admin_required(create_permission), name='create_permission'),
    path('permission/<int:pk>/update/', admin_required(update_permission), name='update_permission'),
    path('permission/<int:pk>/delete/', admin_required(delete_permission), name='delete_permission'),

    path('assign-role/', assign_role_to_user, name='assign_role_to_user'),
    path('assign-permission/', assign_permission_to_role, name='assign_permission_to_role'),
    
    path('user-roles/<int:user_id>/', get_user_roles, name='get_user_roles'),
    path('user-permissions/<int:user_id>/', get_user_permissions, name='get_user_permissions'),

]

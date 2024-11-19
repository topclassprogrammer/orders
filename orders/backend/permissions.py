from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from backend import models


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        if (hasattr(obj, 'user') and obj.user != request.user) or \
                (not hasattr(obj, 'user') and obj != request.user):
            raise PermissionDenied('You cannot get or modify object that does not belong to you')
        return True


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user.role.name != models.RoleChoices.ADMIN:
            raise PermissionDenied('You cannot get or modify any roles because you do not have admin role')
        return True


class HasShop(BasePermission):
    def has_permission(self, request, view):
        if not hasattr(request.user, 'shop'):
            raise PermissionDenied('You do not have shop')
        return True


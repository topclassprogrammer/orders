from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from backend import models
from backend.auth import perform_authentication


class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        request = perform_authentication(request)
        return request.user.is_authenticated


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        conditions = {
            'shop': 'obj.user != request.user',
            'user': 'obj != request.user',
            'address': 'obj.user != request.user',
            'item': 'obj.shop.user != request.user',
            'propertyvalue': 'obj.item.shop.user != request.user'
        }
        model_name = obj._meta.model.__name__.lower()
        if eval(conditions[model_name]):
            raise PermissionDenied('You cannot get or modify object that does not belong to you')
        return True


class HasShop(BasePermission):
    def has_permission(self, request, view):
        if not hasattr(request.user, 'shop'):
            raise PermissionDenied('You do not have shop')
        return True


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user.role.name != models.RoleChoices.ADMIN:
            raise PermissionDenied('You cannot get and/or modify this object because you do not have admin role')
        return True





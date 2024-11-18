from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'user') and obj.user != request.user:
            raise PermissionDenied('You cannot modify shop does not belong to you')
        elif not hasattr(obj, 'user') and request.user != obj:
            raise PermissionDenied('You cannot modify account does not belong to you')
        return True

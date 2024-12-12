from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission
from rest_framework.viewsets import ModelViewSet

from backend import models, views


class IsAdmin(BasePermission):
    """Allow access only to admin users."""
    def has_permission(self, request, view) -> bool:
        """Determines if the request user has admin permissions."""
        if request.user.role.name != models.RoleChoices.ADMIN:
            raise PermissionDenied('You cannot get and/or modify this object because you do not have admin role')
        return True


class HasShop(BasePermission):
    """Allow access only to users with a shop role."""
    def has_permission(self, request, view) -> bool:
        """Determines if the request user has shop permissions."""
        if request.user.role.name != models.RoleChoices.SHOP:
            raise PermissionDenied('You do not have shop role')
        try:
            models.Shop.objects.get(user=request.user)
        except models.Shop.DoesNotExist:
            raise PermissionDenied('You have not created any shop yet')
        return True


class IsOwner(BasePermission):
    """Permission class to allow access only to resource owners."""
    def has_permission(self, request, view) -> bool:
        """Determines if the request user can perform an action on the resource."""
        if isinstance(view, views.OrderView):
            if view.__dict__['action'] == ModelViewSet.create.__name__:
                if 'address' not in request.data:
                    raise PermissionDenied(f"You must provide field 'address'")
                address_id = request.data['address']
                try:
                    address = models.Address.objects.get(id=address_id)
                except (models.Address.DoesNotExist, ValueError) as err:
                    raise PermissionDenied(err)

                if address.user != request.user:
                    raise PermissionDenied(f"{models.Address.__name__} with id {address_id} doesn't belong to you")
        return True

    def has_object_permission(self, request, view, obj) -> bool:
        """Determines if the request user can access a specific resource object."""
        conditions = {
            'user': 'obj != request.user',
            'shop': 'obj.user != request.user',
            'address': 'obj.user != request.user',
            'item': 'obj.shop.user != request.user',
            'propertyvalue': 'obj.item.shop.user != request.user',
            'order': 'obj.user != request.user',
            'orderitem': 'obj.order.user != request.user'
        }
        model_name = obj._meta.model.__name__.lower()
        if eval(conditions[model_name]):
            raise PermissionDenied('You cannot get or modify object that does not belong to you')
        return True

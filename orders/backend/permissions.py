from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from backend import models


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user.role.name != models.RoleChoices.ADMIN:
            raise PermissionDenied('You cannot get and/or modify this object because you do not have admin role')
        return True


class HasShop(BasePermission):
    def has_permission(self, request, view) -> bool:
        if request.user.role.name != models.RoleChoices.SHOP:
            raise PermissionDenied('You do not have shop role')
        try:
            models.Shop.objects.get(user=request.user)
        except models.Shop.DoesNotExist:
            raise PermissionDenied('You have not created any shop yet')
        return True


class HasShop(BasePermission):
    def has_permission(self, request, view):
        if request.user.role.name != models.RoleChoices.SHOP:
            raise PermissionDenied('You do not have shop')
        return True


class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        request = perform_authentication(request)
        return request.user.is_authenticated


class IsOwner(BasePermission):
    def has_permission(self, request, view):
        from backend.views import OrderView
        if isinstance(view, OrderView):
            if view.__dict__['action'] == 'create':
                fields = ['id', 'address']
                for field in fields:
                    if field not in request.data:
                        raise PermissionDenied(f"You must provide field '{field}'")

                order_id = request.data['id']
                try:
                    order = models.Order.objects.get(id=order_id)
                except (models.Order.DoesNotExist, ValueError) as err:
                    raise PermissionDenied(err)

                address_id = request.data['address']
                try:
                    address = models.Address.objects.get(id=address_id)
                except (models.Order.DoesNotExist, ValueError) as err:
                    raise PermissionDenied(err)

                if address.user != request.user:
                    raise PermissionDenied(f"{models.Address.__name__} with id {address_id} doesn't belong to you")
                if order.user != request.user:
                    raise PermissionDenied(f"{models.Order.__name__} with id {order_id} doesn't belong to you")

        return True

    def has_object_permission(self, request, view, obj):
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

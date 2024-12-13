from rest_framework.routers import DefaultRouter

from backend.views import AddressView, BrandView, CategoryView, ItemView, \
    ModelView, OrderItemView, OrderView, PropertyNameView, PropertyValueView, \
    RoleView, ShopView, UserView

router = DefaultRouter()
router.register("user", UserView, basename="user")
router.register("role", RoleView, basename="role")
router.register("shop", ShopView, basename="shop")
router.register("address", AddressView, basename="address")
router.register("brand", BrandView, basename="brand")
router.register("model", ModelView, basename="model")
router.register("category", CategoryView, basename="category")
router.register("item", ItemView, basename="item")
router.register("property-name", PropertyNameView, basename="property-name")
router.register("property-value", PropertyValueView, basename="property-value")
router.register("order", OrderView, basename="order")
router.register("order-item", OrderItemView, basename="order-item")
router.register("active-orders", OrderItemView, basename="active-orders")

urlpatterns = router.urls

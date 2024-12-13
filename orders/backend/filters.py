from django_filters import CharFilter, FilterSet

from backend.models import Item


class ItemFiler(FilterSet):
    """
    Filter set for filtering items based on various attributes.

    Attributes:
        brand (CharFilter): Filter for items based on the brand name.
        model (CharFilter): Filter for items based on the model name.
        category (CharFilter): Filter for items based on the category name.
        shop (CharFilter): Filter for items based on the shop name.
    """
    brand = CharFilter(field_name='brand__name', lookup_expr='icontains')
    model = CharFilter(field_name='model__name', lookup_expr='icontains')
    category = CharFilter(field_name='category__name', lookup_expr='icontains')
    shop = CharFilter(field_name='shop__name', lookup_expr='icontains')

    class Meta:
        model = Item
        fields = ['brand', 'model', 'category', 'shop']

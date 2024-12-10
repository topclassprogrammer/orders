from django_filters import FilterSet, CharFilter

from backend.models import Item


class ItemFiler(FilterSet):
    brand = CharFilter(field_name='brand__name', lookup_expr='icontains')
    model = CharFilter(field_name='model__name', lookup_expr='icontains')
    category = CharFilter(field_name='category__name', lookup_expr='icontains')
    shop = CharFilter(field_name='shop__name', lookup_expr='icontains')

    class Meta:
        model = Item
        fields = ['brand', 'model', 'category', 'shop']

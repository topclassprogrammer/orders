from django.core.cache import caches
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle


class CustomAnonRateThrottle(AnonRateThrottle):
    cache = caches['default']


class CustomUserRateThrottle(UserRateThrottle):
    cache = caches['default']

from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.decorators import api_view


@api_view(['GET'])
def api_root(request, format=None):
    response = Response({
        'sign-in': reverse('sign-in', request=request, format=format),
        'email-verify': reverse('email-verify', request=request, format=format),
        'login': reverse('login', request=request, format=format)
    })

    return response

from django.conf import settings
from django.conf.urls.static import static
from django.urls import path
from .views import ProductAPIView, FileUploadView

urlpatterns = [
    path('products/', ProductAPIView.as_view()),
    path('products/<str:pk>', ProductAPIView.as_view()),
    path('upload/', FileUploadView.as_view())

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
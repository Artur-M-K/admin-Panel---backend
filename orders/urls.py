from django.urls import path
from .views import OrderAPIView, ExportAPIView, ChartAPIView

urlpatterns = [
    path('orders/', OrderAPIView.as_view()),
    path('orders/<str:pk>', OrderAPIView.as_view()),
    path('export/', ExportAPIView.as_view()),
    path('chart/', ChartAPIView.as_view()),

]
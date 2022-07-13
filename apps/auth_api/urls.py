# imports
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from . import views

# register urls to the router
router = DefaultRouter()
router.register('profile', views.UserProfile, basename='user-api')

urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.UserRegister.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('login/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('change_password/', views.UserChangePasswordView.as_view(),
         name='change_password'),
    path('reset_password/', views.SendPasswordResetEmailView.as_view(),
         name='reset_password'),
    path('reset_password/<uid>/<token>', views.UserPasswordResetView.as_view(),
         name='reset_password_done'),
]

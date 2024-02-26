from django.urls import path, include
from .views import *

app_name = 'accounts'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogOutView.as_view(), name='logout'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('edit-profile/<int:pk>', EditProfileView.as_view(), name='profile'),
    path('api/V1/', include('accounts.api.V1.urls')),

    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('change-password/done/', ChangePasswordDoneView.as_view(), name='change_password_done'),

    path('ResetPassword/', ResetPasswordView.as_view(), name='reset_password'),
    path('ResetPassword/done/', ResetPasswordView.as_view(), name='reset_password_done'),
    path('Reset/<str:token>', ResetView.as_view(), name='reset'),
    path('Reset/done', ResetDoneView.as_view(), name='reset_done'),
]
"""
🍪 Cookie Utility Module for Authentication
----------------------------------------------------------
This module provides helper functions to manage authentication
cookies in a secure and reusable way across the application.

Functions Included:
- set_auth_cookies(response, access_token, refresh_token):
    Attaches HttpOnly access and refresh tokens to the response object.

Planned Enhancements:
- clear_auth_cookies(response):
    Securely delete auth cookies on logout or session expiration.

Security Notes:
- Cookies are set as HttpOnly to mitigate XSS.
- You should ensure `Secure` and `SameSite` attributes are
  applied based on your deployment mode (production/dev).
"""


from fastapi import Response

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    # Secure, httpOnly, SameSite=Strict to prevent XSS and CSRF attacks
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,         # True in prod, False if testing on localhost without HTTPS
        samesite="strict",
        max_age=900,         # 15 minutes
        path="/"
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=604800,      # 7 days
        path="/refresh"      # restrict refresh token cookie to refresh route only (optional)
    )

#123
from typing import Optional

import json
import base64
import hmac
import hashlib

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "Jxv0SBIbNvGQ3CYIqJdAGhpjsVVBXqKTH/zWHdBmzgo="
PASSWORD_SALT = "47+KWFKxPiAkY1o0CNwxk7GY8bWy2Xzn5flnamLup+4="

def sign_data(data: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_login_from_signed_string(login_signed: str) -> Optional[str]:
    login_base64, sign = login_signed.split(".")
    print(login_base64)
    login = base64.b64decode(login_base64).decode()
    valid_sign = sign_data(login)
    if hmac.compare_digest(valid_sign, sign):
        return login

def verify_password(login: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[login]["password"].lower()
    return password_hash == stored_password_hash



users = {
    "test@mail.ru": {
        "name": "Popa",
        "password": "a7531543b7510212a447cc5dfc3ffe26abfee289b896a7fa60386868152e1d00", #123
        "balance": 100000
    },
    "petr@mai.ru": {
        "name": "Petya",
        "password": "a15e6ce52cd8a18c919e43a0e24cb2bf51c8c19d9622301eab84ba55c2a1f40f", #456
        "balance": 55555
    }
}

@app.get("/")
def index_page(login: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not login:
        return Response(login_page)
    valid_login = get_login_from_signed_string(login)
    if not valid_login:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key="login")
        return response
    try:
        user = users[valid_login]
    except KeyError:
        response =  Response(login_page, media_type="text/html")
        response.delete_cookie(key="login")
        return response
    return Response(f"Hello: {user['name']} <br/>Balance: {user['balance']}", media_type="text/html")


@app.post("/login")
def process_login_page(login: str = Form(...), password: str = Form(...)):
    user = users.get(login)
    if not user or not verify_password(login, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Invalid login information!"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello: {user['name']} <br/>Balance: {user['balance']}"
        }),
        media_type='application/json')

    login_signed = base64.b64encode(login.encode()).decode() + "." + \
        sign_data(login)
    response.set_cookie(key="login", value=login_signed)
    return response



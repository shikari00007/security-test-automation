import os

import jwt
from ariadne.asgi import GraphQL
from flask import request

from models import Order


def decode(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="orders-api")


def create_order():
    data = request.json
    return Order(item=data["item"], quantity=int(data["quantity"]))


graphql_app = GraphQL(schema, introspection=os.environ.get("ENV") != "production")

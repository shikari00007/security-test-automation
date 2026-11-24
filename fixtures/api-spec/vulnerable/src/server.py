import jwt
from ariadne.asgi import GraphQL
from flask import request

from models import Order


def decode(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})


def decode_no_aud(token, key):
    return jwt.decode(token, key, algorithms=["RS256"])


def create_order():
    order = Order(**request.json)
    return order


graphql_app = GraphQL(schema, introspection=True)

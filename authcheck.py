import os
import ssl
import ldap3

from flask import Flask, abort, jsonify, request
from werkzeug.exceptions import HTTPException


class API(Flask):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.register_error_handler(HTTPException, self.error_handler)

    def error_handler(self, e):
        return {"title": f"{e.code}: {e.name}"}, e.code


api = API(__name__)


@api.route("/", methods=["POST"])
def auth():
    if (
        not request.json
        or "username" not in request.json
        or "password" not in request.json
    ):
        abort(400)
    try:
        conn = ldap3.Connection(
            ldap3.Server(
                os.getenv("LDAP_URI"),
                tls=ldap3.Tls(validate=ssl.CERT_REQUIRED),
            ),
            auto_bind=True,
            authentication=ldap3.SASL,
            sasl_mechanism=ldap3.PLAIN,
            sasl_credentials=(
                None,
                request.json["username"],
                request.json["password"],
            ),
        )
    except ldap3.core.exceptions.LDAPBindError:
        abort(401)
    userdn = conn.extend.standard.who_am_i().split(":", 2)[1]
    conn.search(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope=ldap3.BASE,
        attributes=["namingContexts"],
    )
    basedn = conn.response[0]["attributes"]["namingContexts"][0]
    conn.search(
        search_base=basedn,
        search_filter=f"(&(objectClass=groupOfUniqueNames)(uniqueMember={userdn}))",
        attributes="cn",
    )
    groups = []
    if len(conn.response) > 0:
        for group in conn.response:
            groups.append(group["attributes"]["cn"][0])
    conn.unbind()
    if "group" in request.json and request.json["group"] not in groups:
        abort(403)
    return jsonify(
        {"dn": userdn, "username": request.json["username"], "groups": groups}
    )


if __name__ == "__main__":
    api.run(host="127.0.0.1", port=8000, debug=True)

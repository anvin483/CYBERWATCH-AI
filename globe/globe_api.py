from flask import Blueprint, jsonify

from services.feed_manager import get_attacks_from_db

globe_bp = Blueprint(
    "globe",
    __name__
)

@globe_bp.route("/api/globe/attacks")
def attacks():
    return jsonify(get_attacks_from_db())

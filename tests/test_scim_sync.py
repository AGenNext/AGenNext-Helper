from agennext_helper.scim_sync import SCIMClient


def test_normalize_user_extracts_standard_fields():
    raw = {
        "id": "u1",
        "userName": "alice@example.com",
        "active": True,
        "displayName": "Alice Example",
        "emails": [{"value": "alice@example.com", "primary": True}],
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "department": "engineering"
        },
        "groups": [{"display": "developers"}],
        "entitlements": [{"value": "agent.run"}],
    }

    user = SCIMClient.normalize_user(raw)

    assert user.id == "u1"
    assert user.user_name == "alice@example.com"
    assert user.email == "alice@example.com"
    assert user.department == "engineering"
    assert user.groups == ["developers"]
    assert user.entitlements == ["agent.run"]


def test_normalize_group_extracts_members():
    raw = {
        "id": "g1",
        "displayName": "Engineering",
        "members": [{"value": "u1"}, {"value": "u2"}],
    }

    group = SCIMClient.normalize_group(raw)

    assert group.id == "g1"
    assert group.display_name == "Engineering"
    assert group.members == ["u1", "u2"]

# RP-specific interoperability exceptions kept separate from core CTAP logic.

DISCORD_RP_ID = "discord.com"


def should_store_discoverable(rp_id: str, requested: bool) -> bool:
    # Keep Discord credentials findable despite its rk=false registration.
    # Discord's security-key registration requests a non-discoverable credential,
    # but its passwordless login later omits the allow-list. Other RPs follow
    # the requested resident-key option unchanged.
    return requested or rp_id == DISCORD_RP_ID

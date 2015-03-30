from .. identity import core as identity_core
def identify(source):
    for packet in source:
        identity_core.root_identify(packet)
        yield packet

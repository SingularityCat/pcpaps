
# 
#
def filter(source, deny=None, permit=None):
    if permit is None:
        permit = set()
    if deny is None:
        deny = set()

    for packet in source:
        yield packet

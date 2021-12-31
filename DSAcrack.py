from Crypto.PublicKey import DSA
from DSAregenK import DSAregenK

import logging
LOG = logging.getLogger('DSAregenK')

def public_key():
#   public_key =    y: public exponent
#                   g: group generator
#                   p: prime
#                   q: subprime
    LOG.info("insert y: ")
    y = int(input())
    LOG.info("insert g: ")
    g = int(input())
    LOG.info("insert p: ")
    p = int(input())
    LOG.info("insert q: ")
    q = int(input())

    return DSA.construct((y, g, p, q))

def known_message():
#    mA =    h_m: hash message H(m)
#           (r,s): digital signature components
    LOG.info("insert H(m) (hex): ")
    h = bytes.fromhex(input())

    LOG.info("insert r: ")
    r = int(input())

    LOG.info("insert s: ")
    s = int(input())

    return h, (r, s)

if __name__ == '__main__':
    LOG.setLevel(logging.INFO)
    logging.debug('-- on --')
    LOG.info('---- start inserting known message and attributes ----')

#   returns DSA object
    pk = public_key()

#   returns message object
    LOG.info('---- Input -- mA ----')
    mA = known_message()
    LOG.info('---- Input -- mB ----')
    mB = known_message()
    LOG.info('---- input complete ----')

#   organize test data
    data = []
    data.append(mA)
    data.append(mB)

# ============================================================
#  Begin ATTACK Code :)
# ============================================================
    LOG.debug('---- attack weak coefficient k ----')
    a = DSAregenK(pubkey=pk)
    for h, (r, s) in data:
        a.add((r, s), h)
    priv_key = ''
    for re_privkey in a.run(asDSAobj=True):
        LOG.info(f'Reconstructed private_key: {repr(re_privkey)} | x={re_privkey.x}')
        priv_key = re_privkey
    LOG.debug('----------------------------------------------------------')

# ============================================================
#  Verify attack result by calculating y
#    y = (g ** x) mod p
# ============================================================
    LOG.debug('---- Verify by x ----')
    verify_y = pow(priv_key.g, priv_key.x, priv_key.p)
    LOG.debug(f'Calculated y: {verify_y}')
    LOG.debug(f'Inserted y: {pk.y}')
    if verify_y == pk.y:
        LOG.info('Verified! Successfully reconstructed x!!!')
    else:
        LOG.info('Fail to find real x...')

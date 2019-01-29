"""
Unit tests for the DetachedSignature of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from test.unit.descriptor import get_resource

from stem.descriptor.networkstatus import (
  DetachedSignature,
  DocumentDigest,
  DocumentSignature,
  _parse_file_detached_sigs,
)

BLOCK1 = """
-----BEGIN SIGNATURE-----
dVUvw+7/I16XCXuj5aFtrk1akRXx+/j1NGY+vUDFkZgNNEVoU4i2DHJl1rnPjF2R
PMv8bh0kT3R3MisMGa5htEG9M6fETZnGajvGzkKMH9M91lBNCyJ2ZV7Y+bHn9EfH
xdsnX79y/MOT5xerKfn5/VHHeTuQeg9RCsNFdYFYlQPPiu7LRzH6iZKbjJilLfUk
TLHcK6GPnGZB4EQAB1s3m29trBH4sU7scVjfd5ypGI/hLLD+fyMlKJvMBDuc3Zp9
h2ipkL0YSzOV/4W8DsQg+kRrUBgVEr4DwP/sC26ekiNniVPUXzaxrzIIHmkUWhNt
WNYsdOUeAUxJx+JSyr4kMA==
-----END SIGNATURE-----
""".strip()

BLOCK2 = """
-----BEGIN SIGNATURE-----
Q+qwfKSwbCiJQRPRdI31h3mXgUQBPzjp7e2eZ656EVDT1PatFGx+7KBgDa7yMNwE
bzJqdViMhiBVMglp5ZLQ4SBH1QZjgPGns4Zh1pw//yP5DvAbL9b7B7Pa4hjKGFEY
wVWYdUnFV9XZp+NNes/b2WfbKRifSM1E1Hg3gxuSM16VNZKBsgiABaR3PTYltKs0
oWF3nIWJSAqZ52PlfysIcU0IHiu/KvUCRB7zhHSTTQi1+k00ljxaiL8/vlcs9fIN
WED+BbI7ulc8jp7melpsfO5WzbO4VaY+PYQxV6cH+5wdlPCRMmVH0FZHf1O7V2WS
+VjRvqJcnC6CDVdsj9KIvKqEzTI9KiWfSA62W6c5gqJGUiBwsVqPkOCjhVVs1RQk
py02o9ZDW6crDjqttiGNKgcAzxifcCsoACPLTD6IGUoG7CqpMoyTvpkLdb6BeYSk
atbVl+Q43EstAVMBLyjYK0NZDstol6lBSN3S6rZLH1sH+4LhucJuxR4/v1ccG4Ut
-----END SIGNATURE-----
""".strip()

BLOCK3 = """
-----BEGIN SIGNATURE-----
YEoDpg0vesJ2OSwMNFb7ZkKe17rLNp5T3VhJsyI9U1ggkEuYMIUVLq01aNqFg51O
yaRlnC6/4eSUDanE4jD7GsIQE5JXJjy8p8NwkY1tLSnFaHjmWJnqJEYxKcN84/NZ
0x55TZKMpoJKH4g3ECxhXCwChz8ICjsElgyWiOmafMPxLh3cqfDq+rDsAxWShWs6
qB/E1LU+Ikg5tl+D4xPCdpnODp+eDrjiyIfnVZ1qw68MgBkE000etGwxz63+FctJ
m26fMx8Jxx3krU/5HXVPqnUEXLvRAV0sdiX0/riK1spSEih6y9oM5pS+4B1wy6Rs
5PiuB36F+JJr4kRzUq7w5g==
-----END SIGNATURE-----
""".strip()

BLOCK4 = """
-----BEGIN SIGNATURE-----
usPMz1JctgKdWTuo0lo2wBzfpX9evtxG9GYmzEeeUGZgrSiRBfk8r3am9MVWfpoP
NZYJJazmBq6bkbFLGTAeaqhBFaAoAq/ZubwOpFFCf1rDhsHZgdY1hwU/p1Oz38T6
MZzwLMSmILWedCmcijkCPFN9j5bJ/5sg2ls1zEIa0z3JzHl3UbzXQa0G0Fsyvedu
cY202F6VJpJee6WUq/15PovULtoxUTh9FPnOSEUyUtkUJ8aGm5KNuvY7qYf3Z6Ar
BlTtZuRRhDWdEYLq0QMfhkJHToUuZsL8eNMasG/9OQnnxI5oA+nsjsqbAO2DGMiX
f6v9XU382cMo4N6yu4OmuA==
-----END SIGNATURE-----
""".strip()

BLOCK5 = """
-----BEGIN SIGNATURE-----
5XmrTwv+jyeMFeVZUzqYMDn9XqG7D1nd/Z2H5l2FHOYtEYs+FuLsI0w4T1HL8dyN
x8abjhvJTzfk280wUzgsdg1vbZzhZUMIlyOoGl+5PFyREDvjGlsOmMELdGCtBpyD
5Vof2Rm4dR4iJTgqx42c219nlmKPVcqg0yu4lFu6nGCtABA9bn8i2ULlokufx9zp
vPgqj0lIdWpK7jqXUmQ3W9urV+Bxv+3EHq/9M+z/tY/mpbyUlIKOKy9ypIEs/dQ0
5wsr0E68aGkrG2t5b3yTXYjYsRpg6j1IOaoXC1zb9tBsc9r09jXQFZyZlg4krlng
5NRrtugzHmPZWosdece2vCp+t84vOP+9Kw+aZ9OTbbBDRrzdPCTfVVOU0ZxCjVth
Skj92cuj+czAifPkW1h8cWt+twSo+xeZBlMzcPP2XcmlU+pOIPN57hp7tVTFxGm3
B5IsILBdF6oKURy3sGrFv0QW7hHvGLmZMuom3ME0s1IXDsrR8YjQOkdS6FlOFHoT
-----END SIGNATURE-----
""".strip()

BLOCK6 = """
-----BEGIN SIGNATURE-----
QLL+wjRougl+WZzSfDSjMBo5zDVThG8qEeDNi0E+cwnGt4J2GeCd/sPzyfnnJ2nM
k2MFDFG018scR1oLH7G2c2SD09Wpzl50HXKsRPWgHe9UO7zAY5O4Jq17l4nzwbR4
ynrucQxYqK19aq0FB9JLWy2FKrZlKY59XZnRiGrQSIXndOxgPY4WGXA5qlft8Bu4
Y4HSXsFDpc751mPopcHxRp6A7kHQopoNKKIaIkhrRwxoQgkPzQKegMzncFIvQaMJ
SkYvemmKnuFFmLHYKMjTy0YA5oTkmYgFao15gMeR4nNwuqwxwJ7YLEeCTW+D3avi
9kxIfImiXH9dU7FOyjc1UQ==
-----END SIGNATURE-----
""".strip()


class TestDetachedSignature(unittest.TestCase):
  def test_from_str(self):
    sig = DetachedSignature.create()
    self.assertEqual(sig, DetachedSignature.from_str(str(sig)))

  def test_minimal(self):
    """
    Parses a minimal detached signature.
    """

    sig = DetachedSignature.create()

    self.assertEqual('6D3CC0EFA408F228410A4A8145E1B0BB0670E442', sig.consensus_digest)
    self.assertTrue(sig.valid_after is not None)
    self.assertTrue(sig.fresh_until is not None)
    self.assertTrue(sig.valid_until is not None)
    self.assertEqual([], sig.additional_digests)
    self.assertEqual([], sig.additional_signatures)
    self.assertEqual([], sig.signatures)
    self.assertEqual([], sig.get_unrecognized_lines())

  def test_real_detached_signatures(self):
    """
    Checks that actual detached signatures can be properly parsed.
    """

    expected_additional_sigs = [
      DocumentSignature('sha256', '0232AF901C31A04EE9848595AF9BB7620D4C5B2E', 'CD1FD971855430880D3C31E0331C5C55800C2F79', BLOCK1, flavor = 'microdesc'),
      DocumentSignature('sha256', '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4', '1F4D49989DA1503D5B20EAADB0673C948BA73B49', BLOCK2, flavor = 'microdesc'),
      DocumentSignature('sha256', '23D15D965BC35114467363C165C4F724B64B4F66', 'A2E5511319AD43DF88EABFB8BB1FFD767D005601', BLOCK3, flavor = 'microdesc'),
    ]

    expected_sigs = [
      DocumentSignature('sha1', '0232AF901C31A04EE9848595AF9BB7620D4C5B2E', 'CD1FD971855430880D3C31E0331C5C55800C2F79', BLOCK4),
      DocumentSignature('sha1', '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4', '1F4D49989DA1503D5B20EAADB0673C948BA73B49', BLOCK5),
      DocumentSignature('sha1', '23D15D965BC35114467363C165C4F724B64B4F66', 'A2E5511319AD43DF88EABFB8BB1FFD767D005601', BLOCK6),
    ]

    with open(get_resource('detached_signatures'), 'rb') as sig_file:
      sig = next(_parse_file_detached_sigs(sig_file, 'dir-key-certificate-3 1.0'))
      self.assertEqual('244E0760BB0B1E5418A4A014822F804AFE0CC3D6', sig.consensus_digest)
      self.assertEqual(datetime.datetime(2018, 11, 22, 20, 0), sig.valid_after)
      self.assertEqual(datetime.datetime(2018, 11, 22, 21, 0), sig.fresh_until)
      self.assertEqual(datetime.datetime(2018, 11, 22, 23, 0), sig.valid_until)
      self.assertEqual([DocumentDigest('microdesc', 'sha256', 'EC7F220E415F62394565259F9E44133800F749BFEFB358A3D7F622B8A1728A47')], sig.additional_digests)
      self.assertEqual(9, len(sig.additional_signatures))
      self.assertEqual(expected_additional_sigs, sig.additional_signatures[:3])
      self.assertEqual(9, len(sig.signatures))
      self.assertEqual(expected_sigs, sig.signatures[:3])
      self.assertEqual([], sig.get_unrecognized_lines())

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    sig = DetachedSignature.create({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], sig.get_unrecognized_lines())

  def test_missing_fields(self):
    """
    Parse a detached signature where a mandatory field is missing.
    """

    mandatory_fields = (
      'consensus-digest',
      'valid-after',
      'fresh-until',
      'valid-until',
    )

    for excluded_field in mandatory_fields:
      content = DetachedSignature.content(exclude = (excluded_field,))
      self.assertRaises(ValueError, DetachedSignature, content, True)

      sig = DetachedSignature(content, False)

      if excluded_field == 'consensus-digest':
        self.assertEqual(None, sig.consensus_digest)
      else:
        self.assertEqual(40, len(sig.consensus_digest))

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    sig = DetachedSignature.create({'consensus-digest': '6D3CC0EFA408F228410A4A8145E1B0BB0670E442\n\n\n'})
    self.assertEqual('6D3CC0EFA408F228410A4A8145E1B0BB0670E442', sig.consensus_digest)

  def test_time_fields(self):
    """
    Parses invalid published, valid-after, fresh-until, and valid-until fields.
    All are simply datetime values.
    """

    expected = datetime.datetime(2012, 9, 2, 22, 0, 0)
    test_value = '2012-09-02 22:00:00'

    sig = DetachedSignature.create({
      'valid-after': test_value,
      'fresh-until': test_value,
      'valid-until': test_value,
    })

    self.assertEqual(expected, sig.valid_after)
    self.assertEqual(expected, sig.fresh_until)
    self.assertEqual(expected, sig.valid_until)

    test_values = (
      '',
      '   ',
      '2012-12-12',
      '2012-12-12 01:01:',
      '2012-12-12 01:a1:01',
    )

    for test_value in test_values:
      content = DetachedSignature.content({'valid-after': test_value})
      self.assertRaises(ValueError, DetachedSignature, content, True)

      sig = DetachedSignature(content, False)
      self.assertEqual(None, sig.valid_after)

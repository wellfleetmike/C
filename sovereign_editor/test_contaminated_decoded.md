# Decoded view of test_contaminated.txt
# Every non-whitelist character rendered as [U+XXXX]

# Sovereign Editor Self-Test Contamination Sample
# Each line below contains one attack vector.
# The scanner should detect every non-whitelist character.

Test 01 (homoglyph): p[U+0430]ssword: hunter2
Test 02 (variation_selector): click here[U+FE0F] to verify
Test 03 (tag_block): Run this command[U+E0041] immediately
Test 04 (private_use_basic): version[U+E000] 1.0.0
Test 05 (mathematical_alphanumeric): [U+1D400]pproved by admin
Test 06 (zero_width): user[U+200B]name=admin
Test 07 (non_standard_whitespace): rm[U+00A0]-rf /tmp/sensitive
Test 08 (control_character): alert[U+0007] the operator

Legacy code from the conference version of the paper: it needs the original MySQL database (available on request only) and raw memory pages that are not redistributed (`dmps.zip` is excluded from this repository and deposited in a restricted-access Zenodo record).

## Extraction and analysis process after obtain the collision pages from APOTHEOSIS.
-----------------------------------------------------------------------------------
1. **extract_collision_pages.py** --> extract_page.py
2. **analyze_collisions.py** --> cmp_pages.py
3. **displace_and_hash.py** --> cmp_pages.py, dist_bytes.py, hashes.py
4. **analyze_results.py** (needs the output of displace_and_hash.py)
5. **test_hashes.py** --> hashes.py
6. **plot_test_hashes.py** (needs the output of test_hashes.py)

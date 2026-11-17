# Circuit benchmarks (WASM)

Machine: Apple M3 Max, 14 logical cores, 36 GiB · Darwin 25.6.0 · Node v24.15.0 (V8 13.6.233.17-node.48)
Stack: `@aztec-foundation/bb.js@7.0.0-nightly.20261110` (WASM backend) + `@noir-lang/acvm_js@1.0.0-rc.5` · commit `e5c66f5` · 5 samples per row, each a fresh process

A proof is a Chonk fold of a whole pipeline (apps + noir-zk kernels + hiding kernel), so numbers are per pipeline.
Values are median (min–max). Threads: 1 = no SharedArrayBuffer (plain WKWebView), 6 = iPhone 17 core count.
This is V8 on a Mac: expect a phone (JavaScriptCore, slower cores, iOS memory limits, wasm32 4 GiB cap) to be slower — treat these as a lower bound.

## Pipelines

| Pipeline | Threads | Circuits | Σ gates | Witness ms | Prove ms | **Witness + prove ms** | Peak footprint MiB | Peak RSS MiB | Verify ms | Proof B (compressed) | VK B |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| identity_register_de_bp384_bp256 | 1 | 9 | 678,538 | 3787 (3745–3840) | 22313 (22225–22733) | **26100 (26002–26520)** | 1218 (1213–1237) | 1405 (1393–1409) | 124.7 (124.3–131.0) | 40192 (23552) | 3808 |
| identity_register_de_bp384_bp256 | 6 | 9 | 678,538 | 3815 (3752–4033) | 6227 (6218–6407) | **10040 (9970–10440)** | 1292 (1288–1362) | 1474 (1468–1546) | 53.5 (53.2–54.5) | 40192 (23552) | 3808 |
| identity_register_us_rsa4096_rsa2048 | 1 | 9 | 424,113 | 594 (593–600) | 15956 (15945–16001) | **16550 (16540–16595)** | 717 (715–721) | 756 (755–760) | 125.4 (124.8–125.7) | 40192 (23552) | 3808 |
| identity_register_us_rsa4096_rsa2048 | 6 | 9 | 424,113 | 595 (591–599) | 4483 (4471–4489) | **5076 (5069–5088)** | 781 (781–791) | 817 (816–897) | 53.3 (53.1–53.4) | 40192 (23552) | 3808 |
| member_resolve | 1 | 5 | 83,553 | 45 (45–45) | 7650 (7642–7654) | **7695 (7687–7700)** | 685 (685–686) | 751 (741–751) | 125.2 (124.9–125.5) | 40192 (23552) | 3808 |
| member_resolve | 6 | 5 | 83,553 | 45 (45–46) | 2141 (2140–2144) | **2186 (2185–2190)** | 756 (754–757) | 829 (821–831) | 53.4 (53.4–53.8) | 40192 (23552) | 3808 |
| member_transfer | 1 | 11 | 215,972 | 320 (319–321) | 11846 (11813–11849) | **12166 (12133–12170)** | 736 (735–741) | 813 (809–816) | 125.0 (124.8–125.5) | 40192 (23552) | 3808 |
| member_transfer | 6 | 11 | 215,972 | 321 (320–327) | 3348 (3341–3350) | **3669 (3661–3677)** | 802 (801–804) | 891 (884–896) | 53.3 (53.2–53.6) | 40192 (23552) | 3808 |

## Circuits

Witness ms is the median at 1 thread(s) (ACVM is single-threaded). Dyadic = the power-of-two size bb proves at.

| Pipeline | # | Circuit | Role | ACIR opcodes | Gates | Dyadic | Witness ms |
|---|---:|---|---|---:|---:|---:|---:|
| identity_register_de_bp384_bp256 | 0 | dsc_ecdsa_bp384_sha384_tbs700 | app | 146,312 | 336,148 | 524,288 | 2226.7 (2183.5–2242.8) |
| identity_register_de_bp384_bp256 | 1 | kernel_init | kernel | 344 | 12,375 | 16,384 | 1.5 (1.5–1.6) |
| identity_register_de_bp384_bp256 | 2 | sod_ecdsa_bp256_sha256_tbs700 | app | 42,461 | 132,966 | 262,144 | 669.2 (664.2–678.4) |
| identity_register_de_bp384_bp256 | 3 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.4 (2.4–2.6) |
| identity_register_de_bp384_bp256 | 4 | document_sha256_sha512_lds512 | app | 21,641 | 77,571 | 131,072 | 91.0 (90.4–95.0) |
| identity_register_de_bp384_bp256 | 5 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.4 (2.4–2.5) |
| identity_register_de_bp384_bp256 | 6 | register | app | 834 | 4,202 | 8,192 | 1.4 (1.4–1.4) |
| identity_register_de_bp384_bp256 | 7 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.3 (2.3–2.3) |
| identity_register_de_bp384_bp256 | 8 | kernel_hiding | hiding | 150 | 37,498 | 65,536 | 1.0 (1.0–1.0) |
| identity_register_us_rsa4096_rsa2048 | 0 | dsc_rsa_pkcs1v15_4096_sha256_tbs700 | app | 21,564 | 151,951 | 262,144 | 367.3 (366.3–367.8) |
| identity_register_us_rsa4096_rsa2048 | 1 | kernel_init | kernel | 344 | 12,375 | 16,384 | 1.4 (1.4–1.4) |
| identity_register_us_rsa4096_rsa2048 | 2 | sod_rsa_pkcs1v15_2048_sha256_tbs700 | app | 19,411 | 74,343 | 131,072 | 99.6 (99.4–100.7) |
| identity_register_us_rsa4096_rsa2048 | 3 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.4 (2.4–2.7) |
| identity_register_us_rsa4096_rsa2048 | 4 | document_sha256_sha256_lds512 | app | 8,840 | 65,966 | 131,072 | 18.1 (18.0–19.5) |
| identity_register_us_rsa4096_rsa2048 | 5 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.4 (2.3–2.5) |
| identity_register_us_rsa4096_rsa2048 | 6 | register | app | 834 | 4,202 | 8,192 | 1.4 (1.4–1.4) |
| identity_register_us_rsa4096_rsa2048 | 7 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.3 (2.3–2.3) |
| identity_register_us_rsa4096_rsa2048 | 8 | kernel_hiding | hiding | 150 | 37,498 | 65,536 | 1.0 (1.0–1.0) |
| member_resolve | 0 | identity_member | app | 170 | 4,729 | 8,192 | 26.3 (26.0–26.5) |
| member_resolve | 1 | kernel_init | kernel | 344 | 12,375 | 16,384 | 2.8 (2.7–2.8) |
| member_resolve | 2 | escrow_resolve | app | 58 | 3,025 | 4,096 | 0.7 (0.7–0.7) |
| member_resolve | 3 | kernel_step | kernel | 624 | 25,926 | 32,768 | 4.0 (3.9–4.0) |
| member_resolve | 4 | kernel_hiding | hiding | 150 | 37,498 | 65,536 | 1.6 (1.6–1.6) |
| member_transfer | 0 | identity_member | app | 170 | 4,729 | 8,192 | 26.3 (26.2–26.7) |
| member_transfer | 1 | kernel_init | kernel | 344 | 12,375 | 16,384 | 2.8 (2.7–2.8) |
| member_transfer | 2 | channel_session | app | 42,161 | 50,127 | 65,536 | 172.0 (171.7–173.1) |
| member_transfer | 3 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.5 (2.5–2.5) |
| member_transfer | 4 | dg1_envelope | app | 41 | 339 | 512 | 0.4 (0.4–0.4) |
| member_transfer | 5 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.3 (2.3–2.4) |
| member_transfer | 6 | transfer_holder | app | 405 | 6,926 | 8,192 | 4.6 (4.6–4.6) |
| member_transfer | 7 | kernel_step | kernel | 624 | 25,926 | 32,768 | 2.3 (2.3–2.3) |
| member_transfer | 8 | channel_envelope | app | 38 | 274 | 512 | 0.3 (0.3–0.3) |
| member_transfer | 9 | kernel_step | kernel | 624 | 25,926 | 32,768 | 3.1 (3.0–3.1) |
| member_transfer | 10 | kernel_hiding | hiding | 150 | 37,498 | 65,536 | 1.0 (1.0–1.0) |

## Prove breakdown

| Pipeline | Threads | bb init (WASM + SRS) ms | Load ms | Accumulate ms | Final prove ms |
|---|---:|---:|---:|---:|---:|
| identity_register_de_bp384_bp256 | 1 | 383 (377–384) | 567 (563–577) | 15091 (15009–15410) | 6655 (6641–6771) |
| identity_register_de_bp384_bp256 | 6 | 231 (226–238) | 480 (474–503) | 4060 (4050–4180) | 1690 (1688–1724) |
| identity_register_us_rsa4096_rsa2048 | 1 | 389 (386–391) | 116 (116–117) | 9164 (9162–9203) | 6666 (6663–6681) |
| identity_register_us_rsa4096_rsa2048 | 6 | 235 (221–238) | 121 (120–121) | 2669 (2662–2675) | 1692 (1688–1695) |
| member_resolve | 1 | 383 (383–384) | 10 (10–10) | 1581 (1579–1584) | 6058 (6050–6064) |
| member_resolve | 6 | 234 (223–239) | 11 (10–11) | 589 (589–591) | 1541 (1540–1543) |
| member_transfer | 1 | 387 (381–389) | 82 (82–83) | 4834 (4829–4856) | 6926 (6901–6929) |
| member_transfer | 6 | 233 (230–235) | 84 (84–85) | 1458 (1456–1460) | 1805 (1800–1806) |

## Method

- Inputs: `bench/fixtures.sh` folds each pipeline natively once and dumps every circuit, its inputs (kernels' too) and the proof; the WASM run replays them.
- Witness = `acvm_js.executeCircuit` per circuit + witness-stack encoding. Prove = bb `chonkStart` → `chonkLoad`/`chonkAccumulate` per circuit → `chonkProve`. Verify = `chonkVerify` against the hiding kernel's VK. bb init (WASM instantiate + SRS) is reported separately, not in prove.
- Memory = whole process from `/usr/bin/time -l`: peak footprint (phys_footprint, the figure iOS's jetsam limit applies to) and peak RSS. Both include Node itself: an empty `node` peaks at 31 MiB footprint / 70 MiB RSS here.
- Checks per sample: the proof verifies, its public outputs equal the native fold's, the native proof verifies in WASM, a tampered one is rejected.
- Proof B = proof as 32-byte fields (what the chain verifies); compressed = bb's point-compressed form.

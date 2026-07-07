# Week 3 — Homework (solo, before the weekend lab / Week 4)

Alone on a lab Linux box. Budget ~1 hour. Goal: service recovery becomes fast and log-driven.

## 1. Service lifecycle, from memory (~15 min)
- [ ] Check `status`, `is-active`, and `is-enabled` for a service
- [ ] Stop it, confirm inactive, start it, confirm active, then restart it

## 2. Logs (~15 min)
- [ ] Show the last 40 lines for a service with `journalctl -u`
- [ ] Find the auth log (`auth.log` or `secure`) and note where failed logins would appear

## 3. Break-and-recover, solo (~20 min)
- [ ] Stop a safe service, then recover it **using its log to confirm it's healthy**
- [ ] Bonus: rename/misconfigure the service's config, watch it fail to start, read the log, fix it,
      restart. Write down what the log told you.

## 4. Verify + patch (~10 min)
- [ ] After recovery, confirm the service actually serves (`ss`/`curl`)
- [ ] Run a package update and re-verify the service still serves

## Bring to the weekend lab / Week 4
- Your notes on what the log said during the break-and-recover
- Your fastest recovery time (we'll try to beat it in the relay)
- One question that came up

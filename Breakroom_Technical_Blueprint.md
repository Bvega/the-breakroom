# The Breakroom — Technical Architecture & Sequential Implementation Blueprint

**Product:** "The Breakroom" — a work-culture social PWA built around the daily **CultureSnap** (photo + 1 sentence), verified-but-anonymizable identity, and a constructive-community tone.
**Stack:** React + Tailwind + Vite (mobile-first PWA SPA) · Node.js (Express REST API) · PostgreSQL 15+
**Sources of truth:** Answers.docx (product decisions), summary-1.docx (privacy architecture + approved suggestions), DayAtWork.docx (feature mechanics: edit windows, soft deletes, char limits, counters, pagination), Discovery Questionnaire (framing).

## Locked product decisions this spec implements

1. **MVP scope:** CultureSnap (photo + ≤280-char caption against a rotating daily prompt), likes, comments, separately-tagged suggestions, user accounts, work-email company verification, hybrid feed (60% industry / 25% company / 15% trending), per-post anonymous toggle. Excluded: DMs, advanced search, native apps, video, analytics dashboards.
2. **Auth:** Magic links for **personal-email** login; **6-digit OTP** (never links) for **work-email** verification, because corporate mail scanners pre-click links.
3. **Privacy isolation:** raw work email is hashed (HMAC-SHA-256 with a server-side pepper held in KMS/env, never in the DB) and the plaintext deleted immediately after OTP dispatch. Only `user_id ↔ company_id` linkage persists. Anonymous posts store **no plaintext author FK**; authorship lives in an AES-256-GCM-encrypted vault row so a full database leak cannot de-anonymize historic anonymous posts.
4. **Compliance Shield:** every uploaded image enters a moderation state machine (`pending_scan → approved | flagged_screen | blurred | rejected`). Screens-of-computers are the primary risk; the composer UI nudges against them and the backend carries structural blur/review hooks.
5. **Behavioral guardrails from the docs:** 60-minute edit window with "edited" badge, soft deletes everywhere, 500ms-optimistic like toggle with server reconciliation, comment ≤400 chars, infinite-scroll pagination (cursor-based, 10/batch), rate limiting on all mutating endpoints.

---

# DELIVERABLE 1 — COMPREHENSIVE DATABASE SCHEMA (PostgreSQL DDL)

Run in order as a single migration set. Requires PostgreSQL 15+.

```sql
-- =====================================================================
-- 000_extensions.sql
-- =====================================================================
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive emails/domains

-- =====================================================================
-- 001_enums.sql
-- =====================================================================
CREATE TYPE user_role            AS ENUM ('member', 'moderator', 'admin');
CREATE TYPE verification_status  AS ENUM ('pending', 'verified', 'revoked', 'expired');
CREATE TYPE snap_status          AS ENUM ('published', 'removed_by_user', 'removed_by_moderator');
CREATE TYPE moderation_state     AS ENUM ('pending_scan', 'approved', 'flagged_screen', 'blurred', 'rejected');
CREATE TYPE interaction_kind     AS ENUM ('comment', 'suggestion');
CREATE TYPE interaction_status   AS ENUM ('active', 'removed_by_user', 'removed_by_moderator');
CREATE TYPE report_target        AS ENUM ('snap', 'interaction', 'user');
CREATE TYPE report_reason        AS ENUM ('harassment', 'defamation', 'doxxing', 'sensitive_screen_content',
                                          'spam', 'hate', 'off_topic', 'other');
CREATE TYPE report_status        AS ENUM ('open', 'reviewing', 'actioned', 'dismissed');
CREATE TYPE feed_scope           AS ENUM ('industry', 'company', 'trending');

-- =====================================================================
-- 002_reference_tables.sql
-- =====================================================================
CREATE TABLE industries (
    industry_id   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          VARCHAR(50) NOT NULL UNIQUE,          -- 'tech', 'saas', 'creative', 'research', 'healthcare'...
    display_name  VARCHAR(80) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE companies (
    company_id    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_name   CITEXT       NOT NULL UNIQUE,         -- 'stripe.com' (registrable domain only)
    display_name  VARCHAR(100) NOT NULL,                -- 'Stripe' (derived, editable by admins)
    is_blocked    BOOLEAN      NOT NULL DEFAULT FALSE,  -- block free-mail domains (gmail.com etc.)
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE daily_prompts (
    prompt_id     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    prompt_text   VARCHAR(140) NOT NULL,                -- "What's your workspace vibe today?"
    active_on     DATE         NOT NULL UNIQUE,         -- exactly one prompt per calendar day (UTC)
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX idx_daily_prompts_active_on ON daily_prompts (active_on DESC);

-- =====================================================================
-- 003_users_auth.sql
-- =====================================================================
CREATE TABLE users (
    user_id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    personal_email  CITEXT       NOT NULL UNIQUE,       -- login identity; NEVER a work email
    display_name    VARCHAR(50)  NOT NULL,
    avatar_url      TEXT,
    bio             VARCHAR(200),
    job_title       VARCHAR(80),                        -- self-declared, shown on verified profiles
    industry_id     UUID         REFERENCES industries(industry_id) ON DELETE SET NULL,
    role            user_role    NOT NULL DEFAULT 'member',
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE, -- FALSE = suspended/banned
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT chk_display_name_len CHECK (char_length(display_name) BETWEEN 2 AND 50)
);
CREATE INDEX idx_users_industry ON users (industry_id) WHERE is_active;

-- Magic-link login tokens for PERSONAL email. Only the SHA-256 hash is stored.
CREATE TABLE auth_magic_links (
    magic_link_id  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email          CITEXT      NOT NULL,                -- target personal email (may pre-date the users row)
    token_hash     CHAR(64)    NOT NULL UNIQUE,         -- hex SHA-256 of the raw token
    expires_at     TIMESTAMPTZ NOT NULL,                -- now() + 15 minutes
    consumed_at    TIMESTAMPTZ,
    request_ip     INET,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_magic_links_email_live ON auth_magic_links (email, expires_at)
    WHERE consumed_at IS NULL;

-- Rotating refresh tokens (opaque, hashed). Access tokens are stateless JWTs (15 min).
CREATE TABLE refresh_tokens (
    refresh_token_id  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash        CHAR(64)    NOT NULL UNIQUE,      -- hex SHA-256 of the raw refresh token
    expires_at        TIMESTAMPTZ NOT NULL,             -- now() + 30 days
    revoked_at        TIMESTAMPTZ,
    replaced_by       UUID        REFERENCES refresh_tokens(refresh_token_id),
    user_agent        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

-- =====================================================================
-- 004_company_verification.sql
-- Privacy contract: the raw work email is NEVER written to any table.
-- work_email_hmac = HMAC-SHA-256(WORK_EMAIL_PEPPER, lowercase(work_email)),
-- computed in the application; the pepper lives in KMS/env, not in Postgres.
-- Its only purpose is preventing one inbox from verifying many accounts.
-- =====================================================================
CREATE TABLE company_verifications (
    verification_id   UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID                NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    company_id        UUID                NOT NULL REFERENCES companies(company_id),
    work_email_hmac   CHAR(64)            NOT NULL,
    status            verification_status NOT NULL DEFAULT 'pending',
    otp_hash          CHAR(64),                          -- hex SHA-256 of 6-digit code; NULL after resolution
    otp_expires_at    TIMESTAMPTZ,                       -- now() + 10 minutes
    otp_attempts      SMALLINT            NOT NULL DEFAULT 0,   -- hard cap 5
    verified_at       TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ         NOT NULL DEFAULT now()
);
-- One inbox can only ever back ONE verified account:
CREATE UNIQUE INDEX uq_verification_work_email
    ON company_verifications (work_email_hmac) WHERE status = 'verified';
-- MVP: one verified company per user:
CREATE UNIQUE INDEX uq_verification_one_per_user
    ON company_verifications (user_id) WHERE status = 'verified';
CREATE INDEX idx_verification_user ON company_verifications (user_id, status);

-- =====================================================================
-- 005_media.sql
-- Images are uploaded to object storage via presigned PUT before the snap
-- exists; the row is claimed at snap creation. moderation_state is the
-- Compliance Shield hook: nothing renders publicly until scan resolution,
-- and 'blurred' serves a server-side blurred derivative instead of the
-- original.
-- =====================================================================
CREATE TABLE media_assets (
    media_id           UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id      UUID             NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    storage_key        TEXT             NOT NULL UNIQUE,   -- 'snaps/2026/07/09/<uuid>.jpg'
    blurred_storage_key TEXT,                              -- derivative written when state = 'blurred'
    content_type       VARCHAR(30)      NOT NULL,          -- image/jpeg | image/png | image/webp
    byte_size          INTEGER          NOT NULL,
    width_px           INTEGER,
    height_px          INTEGER,
    moderation_state   moderation_state NOT NULL DEFAULT 'pending_scan',
    moderation_labels  JSONB            NOT NULL DEFAULT '[]'::jsonb, -- e.g. [{"label":"computer_screen","score":0.91}]
    scanned_at         TIMESTAMPTZ,
    claimed            BOOLEAN          NOT NULL DEFAULT FALSE,       -- TRUE once attached to a snap
    created_at         TIMESTAMPTZ      NOT NULL DEFAULT now(),
    CONSTRAINT chk_media_size  CHECK (byte_size > 0 AND byte_size <= 5242880),  -- 5 MB cap
    CONSTRAINT chk_media_type  CHECK (content_type IN ('image/jpeg','image/png','image/webp'))
);
CREATE INDEX idx_media_pending ON media_assets (created_at) WHERE moderation_state = 'pending_scan';
CREATE INDEX idx_media_unclaimed ON media_assets (created_at) WHERE claimed = FALSE; -- GC sweep

-- =====================================================================
-- 006_snaps.sql
-- Identity isolation rule:
--   Public snap    -> author_user_id set,  anon_display_name NULL.
--   Anonymous snap -> author_user_id NULL, anon_display_name set ('BlueFox_7'),
--                     and authorship exists ONLY as AES-256-GCM ciphertext in
--                     snap_author_vault (key in KMS/env, never in Postgres).
-- A leaked pg_dump therefore cannot join anonymous snaps back to users.
-- company_id/industry_id are denormalized AT POST TIME so feeds work and so
-- later verification revocation does not rewrite history.
-- =====================================================================
CREATE TABLE culture_snaps (
    snap_id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    author_user_id    UUID         REFERENCES users(user_id) ON DELETE SET NULL,
    is_anonymous      BOOLEAN      NOT NULL DEFAULT FALSE,
    anon_display_name VARCHAR(32),
    company_id        UUID         REFERENCES companies(company_id),
    industry_id       UUID         REFERENCES industries(industry_id),
    prompt_id         UUID         NOT NULL REFERENCES daily_prompts(prompt_id),
    media_id          UUID         NOT NULL UNIQUE REFERENCES media_assets(media_id),
    caption           VARCHAR(280) NOT NULL,
    status            snap_status  NOT NULL DEFAULT 'published',
    is_edited         BOOLEAN      NOT NULL DEFAULT FALSE,
    like_count        INTEGER      NOT NULL DEFAULT 0,
    comment_count     INTEGER      NOT NULL DEFAULT 0,
    suggestion_count  INTEGER      NOT NULL DEFAULT 0,
    hot_score         REAL         NOT NULL DEFAULT 0,   -- recomputed by the trending job
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    edited_at         TIMESTAMPTZ,
    CONSTRAINT chk_caption_len CHECK (char_length(caption) BETWEEN 1 AND 280),
    CONSTRAINT chk_anonymity CHECK (
        (is_anonymous = TRUE  AND author_user_id IS NULL     AND anon_display_name IS NOT NULL) OR
        (is_anonymous = FALSE AND author_user_id IS NOT NULL AND anon_display_name IS NULL)
    )
);
-- Hybrid-feed indexes (partial: only live content):
CREATE INDEX idx_snaps_industry_feed ON culture_snaps (industry_id, created_at DESC, snap_id DESC)
    WHERE status = 'published';
CREATE INDEX idx_snaps_company_feed  ON culture_snaps (company_id, created_at DESC, snap_id DESC)
    WHERE status = 'published';
CREATE INDEX idx_snaps_trending_feed ON culture_snaps (hot_score DESC, created_at DESC)
    WHERE status = 'published';
CREATE INDEX idx_snaps_author        ON culture_snaps (author_user_id, created_at DESC)
    WHERE status = 'published';

-- Encrypted authorship vault for anonymous snaps.
-- author_ciphertext = AES-256-GCM(VAULT_KEY, user_id_uuid_bytes), nonce prepended.
-- author_lookup_hmac = HMAC-SHA-256(VAULT_LOOKUP_PEPPER, user_id) -> lets the
-- owner list/edit/delete their own anonymous snaps without decryption.
CREATE TABLE snap_author_vault (
    snap_id            UUID     PRIMARY KEY REFERENCES culture_snaps(snap_id) ON DELETE CASCADE,
    author_ciphertext  BYTEA    NOT NULL,
    author_lookup_hmac CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_snap_vault_lookup ON snap_author_vault (author_lookup_hmac);

-- =====================================================================
-- 007_engagement.sql
-- =====================================================================
CREATE TABLE snap_likes (
    snap_id     UUID        NOT NULL REFERENCES culture_snaps(snap_id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (snap_id, user_id)
);
CREATE INDEX idx_snap_likes_user ON snap_likes (user_id);

-- Comments AND suggestions share one table, discriminated by kind
-- (per DayAtWork.docx mechanics + Answers.docx "tagged separately").
CREATE TABLE snap_interactions (
    interaction_id    UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    snap_id           UUID               NOT NULL REFERENCES culture_snaps(snap_id) ON DELETE CASCADE,
    author_user_id    UUID               REFERENCES users(user_id) ON DELETE SET NULL,
    is_anonymous      BOOLEAN            NOT NULL DEFAULT FALSE,
    anon_display_name VARCHAR(32),
    kind              interaction_kind   NOT NULL,
    body              VARCHAR(400)       NOT NULL,
    status            interaction_status NOT NULL DEFAULT 'active',
    is_edited         BOOLEAN            NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ        NOT NULL DEFAULT now(),
    edited_at         TIMESTAMPTZ,
    CONSTRAINT chk_body_len CHECK (char_length(body) BETWEEN 1 AND 400),
    CONSTRAINT chk_interaction_anonymity CHECK (
        (is_anonymous = TRUE  AND author_user_id IS NULL     AND anon_display_name IS NOT NULL) OR
        (is_anonymous = FALSE AND author_user_id IS NOT NULL AND anon_display_name IS NULL)
    )
);
CREATE INDEX idx_interactions_snap ON snap_interactions (snap_id, kind, created_at DESC)
    WHERE status = 'active';

CREATE TABLE interaction_author_vault (
    interaction_id     UUID     PRIMARY KEY REFERENCES snap_interactions(interaction_id) ON DELETE CASCADE,
    author_ciphertext  BYTEA    NOT NULL,
    author_lookup_hmac CHAR(64) NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_interaction_vault_lookup ON interaction_author_vault (author_lookup_hmac);

-- =====================================================================
-- 008_reports.sql  (community moderation entry point)
-- =====================================================================
CREATE TABLE reports (
    report_id        UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID          NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    target_type      report_target NOT NULL,
    target_id        UUID          NOT NULL,           -- snap_id | interaction_id | user_id
    reason           report_reason NOT NULL,
    details          VARCHAR(500),
    status           report_status NOT NULL DEFAULT 'open',
    resolved_by      UUID          REFERENCES users(user_id),
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_report_once UNIQUE (reporter_user_id, target_type, target_id)
);
CREATE INDEX idx_reports_open ON reports (created_at) WHERE status IN ('open','reviewing');

-- =====================================================================
-- 009_counter_triggers.sql
-- Denormalized counters kept consistent in-transaction (no app-side races).
-- =====================================================================
CREATE OR REPLACE FUNCTION trg_snap_like_count() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE culture_snaps SET like_count = like_count + 1 WHERE snap_id = NEW.snap_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE culture_snaps SET like_count = GREATEST(like_count - 1, 0) WHERE snap_id = OLD.snap_id;
        RETURN OLD;
    END IF;
    RETURN NULL;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER snap_like_count_trg
AFTER INSERT OR DELETE ON snap_likes
FOR EACH ROW EXECUTE FUNCTION trg_snap_like_count();

CREATE OR REPLACE FUNCTION trg_interaction_count() RETURNS trigger AS $$
DECLARE
    delta INTEGER;
    k     interaction_kind;
    sid   UUID;
BEGIN
    IF TG_OP = 'INSERT' THEN
        delta := 1; k := NEW.kind; sid := NEW.snap_id;
    ELSIF TG_OP = 'UPDATE' AND OLD.status = 'active' AND NEW.status <> 'active' THEN
        delta := -1; k := NEW.kind; sid := NEW.snap_id;   -- soft delete decrements
    ELSIF TG_OP = 'UPDATE' AND OLD.status <> 'active' AND NEW.status = 'active' THEN
        delta := 1; k := NEW.kind; sid := NEW.snap_id;    -- moderator restore
    ELSE
        RETURN COALESCE(NEW, OLD);
    END IF;

    IF k = 'comment' THEN
        UPDATE culture_snaps SET comment_count = GREATEST(comment_count + delta, 0) WHERE snap_id = sid;
    ELSE
        UPDATE culture_snaps SET suggestion_count = GREATEST(suggestion_count + delta, 0) WHERE snap_id = sid;
    END IF;
    RETURN COALESCE(NEW, OLD);
END $$ LANGUAGE plpgsql;

CREATE TRIGGER interaction_count_trg
AFTER INSERT OR UPDATE OF status ON snap_interactions
FOR EACH ROW EXECUTE FUNCTION trg_interaction_count();

-- updated_at maintenance
CREATE OR REPLACE FUNCTION trg_touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER users_touch_trg
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION trg_touch_updated_at();

-- =====================================================================
-- 010_seed.sql (minimum viable reference data)
-- =====================================================================
INSERT INTO industries (slug, display_name) VALUES
 ('tech','Technology'), ('saas','SaaS'), ('creative','Creative & Agencies'),
 ('research','Research & Academia'), ('startup','Startups'), ('healthcare','Healthcare'),
 ('finance','Finance'), ('other','Other');

INSERT INTO companies (domain_name, display_name, is_blocked) VALUES
 ('gmail.com','(free mail)',TRUE), ('outlook.com','(free mail)',TRUE),
 ('yahoo.com','(free mail)',TRUE), ('icloud.com','(free mail)',TRUE),
 ('proton.me','(free mail)',TRUE), ('hotmail.com','(free mail)',TRUE);

INSERT INTO daily_prompts (prompt_text, active_on) VALUES
 ('What''s your workspace vibe today?',        CURRENT_DATE),
 ('Show us the best thing on your desk.',      CURRENT_DATE + 1),
 ('One frame that sums up your morning.',      CURRENT_DATE + 2),
 ('Your view right now — no screens allowed.', CURRENT_DATE + 3),
 ('One word for this week''s culture (Friday)',CURRENT_DATE + 4),
 ('Weekend recharge: what does it look like?', CURRENT_DATE + 5),
 ('Coffee, tea, or chaos?',                    CURRENT_DATE + 6);
```

**Schema design notes (why it satisfies the guardrails):**

- **Leak-proof anonymity.** `culture_snaps.author_user_id` is genuinely `NULL` for anonymous posts; there is no plaintext FK anywhere. The vault ciphertext requires `VAULT_KEY` (KMS/env) and the lookup HMAC requires `VAULT_LOOKUP_PEPPER` — neither is stored in Postgres, so a full DB dump alone cannot de-anonymize history. The `verifications` link (user↔company) exists per the requirements but never joins to anonymous content.
- **Work email destruction.** No column anywhere can hold a work email. Only `work_email_hmac` persists, and only to stop one inbox from verifying multiple accounts.
- **Compliance Shield.** `media_assets.moderation_state` + `blurred_storage_key` + `moderation_labels` give the full structural hook set: pending images are hidden, `flagged_screen` routes to review, `blurred` swaps in the derivative, `rejected` blocks publication.
- **No over-engineering.** Plain relational tables, partial B-tree indexes matched 1:1 to the three feed queries, in-database counter triggers instead of async pipelines, cursor pagination on `(created_at, snap_id)`.

---

# DELIVERABLE 2 — API ENDPOINT CONTRACTS

**Base URL:** `/api/v1` · **Content type:** `application/json` unless noted.

## Global conventions

**Success envelope:** `{ "success": true, "data": { ... } }` (paginated lists add `"nextCursor": "<opaque>|null"`).

**Error envelope (every non-2xx):**
```json
{ "success": false, "error": { "code": "SNAP_EDIT_WINDOW_EXPIRED", "message": "Snaps can only be edited within 60 minutes of posting.", "details": null } }
```
Canonical error codes: `VALIDATION_FAILED` (400), `UNAUTHENTICATED` (401), `TOKEN_EXPIRED` (401), `FORBIDDEN` (403), `NOT_FOUND` (404), `CONFLICT` (409), `RATE_LIMITED` (429), `OTP_INVALID` (400), `OTP_ATTEMPTS_EXCEEDED` (429), `DOMAIN_BLOCKED` (422), `WORK_EMAIL_ALREADY_USED` (409), `MEDIA_NOT_READY` (409), `SNAP_EDIT_WINDOW_EXPIRED` (403), `INTERNAL` (500).

**Authentication middleware (`requireAuth`):**
1. Read `Authorization: Bearer <accessToken>`; missing/malformed → 401 `UNAUTHENTICATED`.
2. Verify JWT signature (HS256, `JWT_ACCESS_SECRET`) and `exp` (TTL 15 min); expired → 401 `TOKEN_EXPIRED` (client then calls `/auth/refresh`).
3. Load `users` row from `sub`; missing or `is_active = FALSE` → 403 `FORBIDDEN`.
4. Attach `req.user = { userId, role, industryId, companyId | null }` (`companyId` from the user's `verified` verification, cached 60 s).
`requireModerator` additionally enforces `role IN ('moderator','admin')`.

**Rate limits (per user or IP, sliding window):** magic-link request 5/hr/email; OTP request 3/hr/user; OTP confirm 5 attempts/verification; snap create 3/day/user (one per prompt is enforced separately: 409 `CONFLICT`); interactions 30/hr; likes 200/hr; reports 20/day. Exceeding → 429 `RATE_LIMITED` with `Retry-After`.

## 2.1 Auth (personal email, magic link)

**POST `/auth/magic-link`** — no auth.
Request: `{ "email": "jane@gmail.com" }`
Success `202`: `{ "success": true, "data": { "message": "If that address exists or is eligible, a sign-in link has been sent." } }` (identical response whether or not the account exists — no user enumeration).
Errors: 400 `VALIDATION_FAILED`, 429 `RATE_LIMITED`.

**POST `/auth/magic-link/verify`** — no auth.
Request: `{ "email": "jane@gmail.com", "token": "<raw token from link>", "displayName": "Jane D." }` (`displayName` required only on first-ever login; ignored otherwise).
Server: hash token → match live `auth_magic_links` row (unconsumed, unexpired) → mark consumed → upsert user → mint tokens.
Success `200`:
```json
{ "success": true, "data": {
    "accessToken": "<jwt-15min>",
    "refreshToken": "<opaque-30d>",
    "user": { "userId": "…", "displayName": "Jane D.", "avatarUrl": null, "industry": null,
              "jobTitle": null, "verifiedCompany": null, "role": "member", "createdAt": "…" } } }
```
Errors: 400 `VALIDATION_FAILED` (bad/expired/consumed token), 400 `VALIDATION_FAILED` (first login without displayName).

**POST `/auth/refresh`** — no auth. Request: `{ "refreshToken": "<opaque>" }`.
Server: hash → match unrevoked/unexpired row → revoke it, insert replacement (rotation; reuse of a revoked token revokes the whole chain).
Success `200`: `{ "success": true, "data": { "accessToken": "…", "refreshToken": "…" } }` · Errors: 401 `UNAUTHENTICATED`.

**POST `/auth/logout`** — `requireAuth`. Request: `{ "refreshToken": "<opaque>" }` → revokes it. Success `200`: `{ "success": true, "data": { "message": "Logged out." } }`

**GET `/auth/me`** — `requireAuth`. Success `200`: same `user` object as above, plus `"verification": { "status": "verified", "company": { "companyId": "…", "displayName": "Stripe" }, "verifiedAt": "…" } | null`.

## 2.2 Company verification (work email, OTP — never links)

**POST `/verification/request`** — `requireAuth`.
Request: `{ "workEmail": "jane.doe@stripe.com" }`
Server sequence (the privacy-critical path):
1. Validate format; extract registrable domain (`stripe.com`); upsert `companies`; if `is_blocked` → 422 `DOMAIN_BLOCKED`.
2. Compute `work_email_hmac`; if another user holds a `verified` row with it → 409 `WORK_EMAIL_ALREADY_USED`.
3. Generate 6-digit OTP; store SHA-256 hash + 10-min expiry on a `pending` verification row (superseding any prior pending row for this user).
4. Send OTP to the work inbox. **Discard the plaintext work email from memory; it is never persisted or logged.**
Success `202`: `{ "success": true, "data": { "message": "Code sent to your work inbox. It expires in 10 minutes.", "companyDisplayName": "Stripe" } }`

**POST `/verification/confirm`** — `requireAuth`. Request: `{ "code": "482913" }`
Server: load pending row → if `otp_attempts >= 5` → 429 `OTP_ATTEMPTS_EXCEEDED`; expired → 400 `OTP_INVALID`; hash-compare (constant-time), increment attempts on miss → 400 `OTP_INVALID`. On match: `status='verified'`, `verified_at=now()`, null out `otp_hash`.
Success `200`: `{ "success": true, "data": { "verification": { "status": "verified", "company": { "companyId": "…", "displayName": "Stripe" }, "verifiedAt": "…" } } }`

**GET `/verification`** — `requireAuth` → current verification object or `null`.
**DELETE `/verification`** — `requireAuth` → sets `status='revoked'`, `revoked_at=now()` ("users can delete verification at any time"; historic snaps keep their denormalized `company_id`). Success `200`: `{ "success": true, "data": { "message": "Verification removed." } }`

## 2.3 Profile & reference data

**PATCH `/users/me`** — `requireAuth`. Request (all optional): `{ "displayName": "…", "bio": "…", "jobTitle": "…", "industryId": "…", "avatarMediaId": "…" }` → updated `user`. Errors: 400, 409 (media not approved).
**GET `/users/:userId`** — `requireAuth`. Public profile: `{ "userId", "displayName", "avatarUrl", "bio", "jobTitle", "industry", "verifiedCompanyDisplayName" }` — **never** returns personal email; **never** includes anonymous content.
**GET `/users/:userId/snaps?cursor&limit`** — `requireAuth`. That user's **public** snaps only. For `me`, includes own anonymous snaps (resolved via `author_lookup_hmac`), each flagged `"isAnonymous": true`.
**GET `/industries`** — no auth → `[{ "industryId", "slug", "displayName" }]`.
**GET `/prompts/today`** — `requireAuth` → `{ "promptId", "promptText", "activeOn", "alreadyPosted": false }`.

## 2.4 Media (Compliance Shield entry point)

**POST `/media/uploads`** — `requireAuth`.
Request: `{ "contentType": "image/jpeg", "byteSize": 2381220 }`
Success `201`: `{ "success": true, "data": { "mediaId": "…", "uploadUrl": "<presigned PUT, 10-min TTL>", "headers": { "Content-Type": "image/jpeg" } } }`
Errors: 400 `VALIDATION_FAILED` (type/size).
After the client PUTs the bytes, the scan worker moves `pending_scan → approved | flagged_screen | rejected` and writes `moderation_labels`; `flagged_screen` may auto-transition to `blurred` (derivative generated with sharp).

**GET `/media/:mediaId/status`** — `requireAuth`, owner only → `{ "mediaId", "moderationState", "labels": [...] }` (composer polls this before enabling Publish).

## 2.5 CultureSnaps

**POST `/snaps`** — `requireAuth`.
Request: `{ "caption": "Third espresso, still Monday.", "promptId": "…", "mediaId": "…", "isAnonymous": true }`
Server: media must be owned by caller, unclaimed, and `approved`/`blurred` (else 409 `MEDIA_NOT_READY`); one snap per user per prompt (409 `CONFLICT`); denormalize caller's `industry_id` + verified `company_id`; if anonymous → generate pseudonym (`Adjective+Animal_+2 digits`), insert snap with `author_user_id = NULL`, and write the vault row **in the same transaction**.
Success `201`: full snap object (below). Errors: 400, 404 (prompt), 409, 429.

**Snap object (all read endpoints):**
```json
{ "snapId": "…", "caption": "…",
  "image": { "url": "<CDN url or blurred derivative>", "state": "approved", "width": 1200, "height": 900 },
  "author": { "isAnonymous": true, "displayName": "BlueFox_7", "avatarUrl": null, "userId": null },
  "company": { "companyId": "…", "displayName": "Stripe" },
  "industry": { "industryId": "…", "displayName": "Technology" },
  "prompt": { "promptId": "…", "promptText": "…" },
  "likeCount": 15, "commentCount": 8, "suggestionCount": 3,
  "viewerHasLiked": false, "viewerIsAuthor": false, "isEdited": false,
  "createdAt": "2026-07-09T10:30:00Z" }
```
For public snaps `author` carries real `userId/displayName/avatarUrl` and `"isAnonymous": false`. `viewerIsAuthor` is resolved for anonymous snaps via the caller's lookup-HMAC — the identity itself is never exposed.

**GET `/feed?type=hybrid|industry|company|trending&cursor=<opaque>&limit=10`** — `requireAuth`.
`hybrid` (default) interleaves per the locked 60/25/15 ratio (6 industry / 2–3 company / 1–2 trending per 10, de-duplicated, backfilled from industry when a bucket is short; `company` bucket empty for unverified users and backfilled). `company` requires verification (403 `FORBIDDEN` otherwise). Cursor is base64 of the three per-bucket keyset positions.
Success `200`: `{ "success": true, "data": [ ...snaps ], "nextCursor": "…" }`

**GET `/snaps/:snapId`** — `requireAuth` → snap object. 404 if not `published` (unless viewer is author/moderator).
**PATCH `/snaps/:snapId`** — `requireAuth`, author only (vault-resolved for anonymous). Request: `{ "caption": "…" }`. >60 min after `created_at` → 403 `SNAP_EDIT_WINDOW_EXPIRED`. Sets `is_edited`, `edited_at`. → snap object.
**DELETE `/snaps/:snapId`** — author (soft delete → `removed_by_user`) or moderator (`removed_by_moderator`). Success `200`: `{ "success": true, "data": { "message": "Snap removed." } }`
**PUT `/snaps/:snapId/like`** — idempotent insert → `{ "liked": true, "likeCount": 16 }`
**DELETE `/snaps/:snapId/like`** — idempotent delete → `{ "liked": false, "likeCount": 15 }`

## 2.6 Comments & Suggestions

**POST `/snaps/:snapId/interactions`** — `requireAuth`.
Request: `{ "kind": "suggestion", "body": "Ask for a monitor arm — changed my life.", "isAnonymous": false }`
Success `201`: interaction object `{ "interactionId", "snapId", "kind", "body", "author": {…same shape as snap author…}, "isEdited", "createdAt", "viewerIsAuthor" }`. Anonymous interactions follow the identical vault pattern.
**GET `/snaps/:snapId/interactions?kind=comment|suggestion|all&cursor&limit=20`** → `{ "data": { "comments": [...], "suggestions": [...] }, "nextCursor" }` when `all`, else a flat list.
**PATCH `/interactions/:id`** — author only, 60-min window, `{ "body": "…" }`.
**DELETE `/interactions/:id`** — author (soft) or moderator.

## 2.7 Reports & moderation

**POST `/reports`** — `requireAuth`. `{ "targetType": "snap", "targetId": "…", "reason": "sensitive_screen_content", "details": "Slack messages readable" }` → `201 { "reportId", "status": "open" }`; duplicate by same reporter → 409 `CONFLICT`.
**GET `/moderation/queue?status=open&cursor`** — `requireModerator` → reports joined with target previews (anonymous targets show pseudonyms only; even moderators don't see vault identities through this endpoint).
**POST `/moderation/reports/:reportId/resolve`** — `requireModerator`. `{ "action": "remove_content" | "blur_image" | "dismiss", "note": "…" }` → applies action, sets `actioned/dismissed`.
**POST `/moderation/media/:mediaId/state`** — `requireModerator`. `{ "state": "approved" | "blurred" | "rejected" }` → manual Compliance Shield override; `blurred` triggers derivative generation.

---

# DELIVERABLE 3 — LLM-READY SEQUENTIAL IMPLEMENTATION ROADMAP

Ten isolated phases. Each block below is a complete, copy-pasteable prompt for an execution-tier coding LLM. Hand them over **in order**; each phase's prompt assumes only the artifacts produced by earlier phases. Wherever a prompt says *"(paste Deliverable 1)"* or *"(paste Deliverable 2)"*, paste that section of this document verbatim.

---

## Phase 1 — Repository scaffold & tooling

```text
You are building "The Breakroom", a work-culture social PWA. Create the monorepo scaffold only — no features yet.

Structure:
breakroom/
├── server/            # Node.js 20 + Express 4 REST API (TypeScript)
│   ├── src/
│   │   ├── config/env.ts        # loads & validates ALL env vars with zod; crash on missing
│   │   ├── db/pool.ts           # single pg.Pool export (node-postgres), reads DATABASE_URL
│   │   ├── middleware/          # (empty for now)
│   │   ├── modules/             # feature modules land here in later phases
│   │   ├── app.ts               # express app: helmet, cors (CORS_ORIGIN env), express.json({limit:'50kb'}), pino-http logging, GET /api/v1/health -> {success:true,data:{status:'ok'}}
│   │   └── server.ts            # boots app on PORT
│   ├── migrations/              # plain .sql files, ordered by numeric prefix
│   ├── scripts/migrate.ts       # runs pending migrations transactionally; tracks applied files in table schema_migrations(filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ)
│   ├── .env.example
│   ├── package.json  tsconfig.json
├── web/               # Vite + React 18 + TypeScript + Tailwind, PWA
│   ├── (vite scaffold with vite-plugin-pwa configured: standalone display, theme color #0F172A, offline app-shell caching only)
│   └── src/lib/api.ts           # typed fetch wrapper: base '/api/v1', JSON envelopes {success,data|error}, attaches Bearer token from an injected token store, auto-calls /auth/refresh once on 401 TOKEN_EXPIRED then retries
└── package.json       # npm workspaces: server, web; scripts: dev (concurrently), migrate, lint, test

Requirements:
- TypeScript strict mode everywhere. ESLint + Prettier configured at root.
- server .env.example must list: DATABASE_URL, PORT, CORS_ORIGIN, JWT_ACCESS_SECRET, JWT_ACCESS_TTL=900, REFRESH_TTL_DAYS=30, MAGIC_LINK_TTL_MIN=15, OTP_TTL_MIN=10, WORK_EMAIL_PEPPER, VAULT_KEY (32-byte base64), VAULT_LOOKUP_PEPPER, S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY, CDN_BASE_URL, EMAIL_FROM, SMTP_URL.
- Vitest wired in both packages with one passing smoke test each (health endpoint via supertest; App renders via @testing-library/react).
- No placeholder comments. Everything you write must run: `npm run dev` serves web on 5173 proxying /api to server on 3000.
Acceptance: npm install && npm run lint && npm test pass; GET /api/v1/health returns the success envelope.
```

---

## Phase 2 — Database migrations & seed

```text
Context: Breakroom monorepo from Phase 1 exists; server/scripts/migrate.ts runs ordered .sql files from server/migrations against DATABASE_URL.

Task: Create migration files 000_extensions.sql through 010_seed.sql containing EXACTLY the following DDL, split by the section comments:

(paste Deliverable 1 SQL verbatim)

Additional work:
- server/src/db/types.ts: hand-written TypeScript interfaces mirroring every table row and every enum (e.g. type ModerationState = 'pending_scan'|'approved'|'flagged_screen'|'blurred'|'rejected').
- server/scripts/seed-dev.ts: inserts 3 fake users, 1 unblocked company ('acme.dev','Acme'), verified rows for 2 users, 6 published snaps (2 anonymous with correctly-encrypted vault rows using the crypto utils STUBBED as direct calls to node:crypto — implement createCipheriv('aes-256-gcm') inline here; Phase 3 will centralize), likes and mixed comments/suggestions. Media rows may point at placeholder storage keys with moderation_state='approved'.
- Add npm script "db:reset": drops & recreates schema (guard: refuses when NODE_ENV=production), migrates, seeds.
Acceptance: db:reset succeeds twice in a row; \d culture_snaps shows the chk_anonymity constraint; inserting a snap violating chk_anonymity fails; deleting a snap_likes row decrements like_count via trigger (write a vitest integration test against a local Postgres for the two counter triggers).
```

---

## Phase 3 — Crypto utilities & auth (magic links + JWT sessions)

```text
Context: Breakroom server with migrated schema (tables: users, auth_magic_links, refresh_tokens). Global envelopes and error codes:

(paste Deliverable 2 "Global conventions" verbatim)

Build server/src/lib/crypto.ts:
- sha256Hex(input: string): string
- hmacHex(pepper: string, input: string): string                       // HMAC-SHA-256
- vaultEncrypt(userId: string): Buffer                                 // AES-256-GCM with VAULT_KEY; output = nonce(12) || tag(16) || ciphertext
- vaultDecrypt(blob: Buffer): string
- lookupHmac(userId: string): string                                   // hmacHex(VAULT_LOOKUP_PEPPER, userId)
- constantTimeEqual(a: string, b: string): boolean                     // timingSafeEqual
- generateOtp(): string (6 digits, crypto.randomInt), generateToken(): string (32 bytes base64url)
Unit-test every function including GCM tamper detection.

Build server/src/middleware/errors.ts (central error class ApiError(code, httpStatus, message, details?) + express error handler emitting the error envelope) and middleware/rateLimit.ts (sliding-window limiter backed by a Postgres table rate_limit_events(key TEXT, ts TIMESTAMPTZ) with an index on (key, ts); helper rateLimit(keyFn, max, windowSec) — add migration 011 for the table).

Build server/src/modules/auth implementing EXACTLY these contracts:

(paste Deliverable 2 section 2.1 verbatim)

Implementation notes:
- Magic-link email: send via SMTP_URL (nodemailer); the link is `${WEB_ORIGIN}/auth/verify?token=...&email=...`; store only sha256Hex(token).
- Identical 202 response whether or not the email maps to a user (no enumeration). New users are created at verify time (displayName required then).
- Access JWT: HS256, payload {sub, role}, TTL from env. Refresh rotation with reuse-detection chain revocation exactly as specified.
- middleware/requireAuth.ts implementing the 4-step logic from the conventions, including the cached verified-company lookup.
Acceptance: supertest suite covers: happy path signup->login->me, expired link, consumed link reuse, refresh rotation, refresh reuse revokes chain, rate limit fires at 6th magic-link request in an hour.
```

---

## Phase 4 — Company verification (OTP, privacy-critical)

```text
Context: Breakroom server with auth from Phase 3. Tables: companies, company_verifications. Crypto utils exist.

Implement server/src/modules/verification to EXACTLY these contracts, including the 4-step server sequence and every listed error code:

(paste Deliverable 2 section 2.2 verbatim)

Hard privacy rules (non-negotiable):
1. The plaintext work email may exist ONLY as a local variable inside the request handler. It must never be written to the DB, cache, queue, or any log line. Add a pino redaction test proving req.body.workEmail is redacted in request logs.
2. Domain extraction: use tldts to get the registrable domain (jane@mail.eng.stripe.com -> stripe.com).
3. OTP storage is sha256Hex only; comparison via constantTimeEqual; attempts increment BEFORE comparison result is returned.
4. On confirm success, null out otp_hash and otp_expires_at.
5. Requesting a new OTP supersedes (expires) any prior pending row for the user.
Also implement GET /verification and DELETE /verification (revocation keeps historic snaps' denormalized company_id untouched — prove it now with a test that inserts a culture_snaps row directly via SQL, revokes the verification, and asserts the snap's company_id is unchanged).
Acceptance: full supertest coverage of: blocked domain 422, duplicate inbox 409, wrong code x5 -> 429, expiry 400, happy path 200, revoke 200; grep of test log output finds no work email string.
```

---

## Phase 5 — Media pipeline & Compliance Shield

```text
Context: Breakroom server; media_assets table exists (states: pending_scan/approved/flagged_screen/blurred/rejected). S3-compatible object storage configured via env (use MinIO locally; @aws-sdk/client-s3 + @aws-sdk/s3-request-presigner).

Implement to EXACTLY these contracts:

(paste Deliverable 2 section 2.4 verbatim)

Components:
1. modules/media/routes.ts — POST /media/uploads (validates type/size, inserts row, returns presigned PUT with 10-min TTL and enforced Content-Type) and GET /media/:mediaId/status (owner-only).
2. modules/media/scanner.ts — the Compliance Shield worker. Interface: scanImage(buffer): Promise<{labels: {label:string, score:number}[]}>. Ship one concrete implementation, HeuristicScanner, that uses sharp to (a) validate the file is a decodable image of the declared type, (b) read dimensions, and (c) flag label 'computer_screen' with score 0.8 when EXIF/metadata or aspect ratio matches common screenshot signatures (aspect ratio within 1% of 16:9/16:10/19.5:9 AND no camera Make/Model EXIF). This is deliberately conservative heuristics — the interface is the hook for a real vision-API provider later, but the shipped code must be fully functional, not a stub.
3. modules/media/worker.ts — polling loop (setInterval 5s, SELECT ... FOR UPDATE SKIP LOCKED on pending_scan rows): download object, run scanner, then: no flags -> 'approved'; 'computer_screen' flagged -> generate blurred derivative (sharp .blur(25), write to blurred_storage_key) and set state 'blurred'; undecodable/oversized -> 'rejected'. Persist moderation_labels and scanned_at. Start the worker from server.ts behind env MEDIA_WORKER=1.
4. GC job: hourly delete of unclaimed media older than 24h (DB row + object).
Acceptance: integration test with MinIO: upload jpeg -> approved; upload synthetic 1920x1080 metadata-stripped png -> blurred with derivative object existing; upload text file renamed .jpg -> rejected.
```

---

## Phase 6 — Prompts, Snaps CRUD & anonymity vault

```text
Context: Breakroom server with auth, verification, media done. Tables: daily_prompts, culture_snaps, snap_author_vault. Crypto utils vaultEncrypt/vaultDecrypt/lookupHmac exist.

Implement to EXACTLY these contracts (snap object shape included):

(paste Deliverable 2 sections 2.3 [prompts + users/me + users/:id lines] and 2.5 [POST /snaps, GET /snaps/:snapId, PATCH, DELETE, likes] verbatim — feed comes in Phase 7)

Implementation notes:
- Pseudonym generator: lib/pseudonym.ts with embedded word lists (60 adjectives, 60 animals) -> 'BlueFox_47'; collision-free per snap (no uniqueness constraint needed; they are per-post).
- POST /snaps must run in ONE transaction: claim media (claimed=TRUE, verify owner + state IN ('approved','blurred')), enforce one-snap-per-prompt via SELECT ... FOR UPDATE + unique check, denormalize industry_id from users and company_id from the caller's verified verification (nullable), insert snap, and when isAnonymous insert snap_author_vault(vaultEncrypt(userId), lookupHmac(userId)).
- Authorization for PATCH/DELETE on anonymous snaps: caller is author iff snap_author_vault.author_lookup_hmac = lookupHmac(req.user.userId). Never decrypt in the request path.
- viewerHasLiked via LEFT JOIN snap_likes; viewerIsAuthor per the same hmac rule (or author_user_id match for public snaps).
- Image URL resolution: state 'blurred' -> CDN_BASE_URL + blurred_storage_key, else original key. pending/rejected snaps cannot exist (creation blocks them).
- PUT/DELETE like endpoints are idempotent (INSERT ... ON CONFLICT DO NOTHING / DELETE ... IF EXISTS) and return fresh counts read after the trigger fires.
- GET /users/:userId/snaps: public snaps by author_user_id; for :userId == caller, UNION own anonymous snaps via vault hmac join, each marked isAnonymous:true.
Acceptance tests must include: anonymous snap row has author_user_id NULL and no plaintext linkage anywhere (assert by querying every column); author can edit within 60 min and gets SNAP_EDIT_WINDOW_EXPIRED after (fake timers); second snap on same prompt -> 409; a different user cannot delete an anonymous snap even knowing its id.
```

---

## Phase 7 — Interactions & Hybrid feed

```text
Context: Breakroom server with snaps live. Tables: snap_interactions, interaction_author_vault. Counter triggers already maintain comment_count/suggestion_count.

Part A — implement to EXACTLY these contracts:

(paste Deliverable 2 section 2.6 verbatim)

Anonymous interactions reuse the identical vault pattern from snaps (encrypt + lookup hmac in the same transaction; authorization via hmac).

Part B — implement GET /feed to EXACTLY this contract:

(paste Deliverable 2 GET /feed block verbatim)

Feed algorithm (modules/feed/service.ts), deliberately simple SQL, no caching layer:
1. Decode cursor -> { industryKey, companyKey, trendingKey } (each a {createdAt, snapId} or {hotScore, createdAt} keyset position; null = start).
2. Bucket queries (keyset pagination against the three partial indexes):
   industry: WHERE industry_id = $viewerIndustry AND status='published' AND (created_at, snap_id) < ($k) ORDER BY created_at DESC, snap_id DESC LIMIT 8
   company:  WHERE company_id  = $viewerCompany  ... LIMIT 4   (skip when unverified)
   trending: WHERE status='published' ORDER BY hot_score DESC, created_at DESC LIMIT 3 with keyset on (hot_score, created_at)
3. Interleave pattern for limit=10: [I,I,I,C,I,T,I,C,I,I] -> 6/2~3/1~2 ≈ 60/25/15; de-duplicate by snap_id preferring the earlier bucket; backfill shortfalls from industry, then trending; users with no industry set fall back to trending+recency.
4. Encode nextCursor from the last-consumed row of each bucket.
Part C — trending job: every 10 minutes recompute for snaps from the last 72h:
   hot_score = (like_count + 2*comment_count + 3*suggestion_count) / power(GREATEST(EXTRACT(EPOCH FROM now()-created_at)/3600,1) + 2, 1.5)
   (single UPDATE statement; older snaps decay to 0 via a second UPDATE setting hot_score=0 WHERE created_at < now()-interval '72 hours' AND hot_score <> 0). Run behind env FEED_JOB=1.
Acceptance: seeded-data tests assert bucket ratios over 30 fetched items, cursor stability (no duplicates/gaps across pages), unverified users receive no company items, and suggestion-heavy snaps outrank like-heavy ones of equal age.
```

---

## Phase 8 — Reports & moderation endpoints

```text
Context: Breakroom server feature-complete for content. Tables: reports; media state machine from Phase 5; requireModerator middleware pattern from conventions.

Implement to EXACTLY these contracts:

(paste Deliverable 2 section 2.7 verbatim)

Notes:
- Target existence is validated per targetType before insert; self-reporting own content -> 400 VALIDATION_FAILED.
- resolve 'remove_content' sets snap/interaction status to removed_by_moderator; 'blur_image' calls the Phase 5 derivative path; 'dismiss' only closes the report.
- Moderation queue previews must render anonymous authors as their pseudonym; assert in tests that no vault decryption function is imported anywhere in the moderation module.
- All resolutions are audit-logged to a new table moderation_actions(action_id UUID PK DEFAULT gen_random_uuid(), report_id UUID REFERENCES reports, moderator_id UUID REFERENCES users, action TEXT NOT NULL, note VARCHAR(500), created_at TIMESTAMPTZ NOT NULL DEFAULT now()) — add migration 012.
Acceptance: supertest covers duplicate report 409, member hitting queue 403, each resolve action's side effect, and the audit row.
```

---

## Phase 9 — Frontend: PWA shell, auth & verification flows

```text
Context: Breakroom web package (Vite+React+TS+Tailwind+vite-plugin-pwa) with the typed api client from Phase 1. Backend contracts:

(paste Deliverable 2 sections 2.1, 2.2, 2.3 verbatim)

Build a mobile-first (design at 390px, fluid to desktop) SPA with react-router v6:
1. Design system (src/ui/): Tailwind config with brand palette (bg slate-950/white duality is NOT needed — single light theme, warm neutral background #FAF9F7, ink #1A1A1A, accent 'breakroom orange' #E8590C, suggestion lime #4D7C0F), Button, Input, OtpInput (6 boxes, auto-advance, paste-splitting), Toast (context-based), Sheet (bottom sheet), Avatar (with generated-initials fallback), Skeleton.
2. Auth flow: /login (email input -> "check your inbox" state), /auth/verify (reads token+email from query, calls verify; first-login variant collects displayName), token store in memory + refreshToken in localStorage, api client auto-refresh already exists — wire it. AuthProvider exposes {user, verification, refresh(), logout()}; route guard redirects unauthenticated users to /login.
3. Onboarding sequence after first login: pick industry (GET /industries, tappable chips) -> optional job title -> optional work-email verification screen -> done. Verification screen: work email input -> OTP entry (10-min countdown, resend after 60s, attempts-exceeded error state) -> success confetti-free confirmation showing the company badge. Must be skippable and re-enterable later from /settings.
4. /settings: edit profile fields, avatar upload (uses POST /media/uploads then PUT to presigned URL then PATCH /users/me with avatarMediaId; poll status until approved), manage/remove verification, logout.
5. PWA: installable, app-shell cached, API responses never cached by the service worker.
Every server error code listed in the contracts must map to a human-readable toast or inline message — build the mapping table in src/lib/errors.ts and exhaustively switch on it.
Acceptance: vitest+RTL tests for OtpInput behavior, AuthProvider refresh-on-401, and the error mapping; manual script in README for the full login->verify walkthrough against the dev server.
```

---

## Phase 10 — Frontend: CultureSnap composer, feed & engagement

```text
Context: Breakroom web app with auth shell (Phase 9). Backend contracts:

(paste Deliverable 2 sections 2.4, 2.5, 2.6, 2.7 [POST /reports only] verbatim, including the snap object shape)

Build:
1. /feed (home): header with feed-scope segmented control (For You | My Company | Trending — 'My Company' locked with a "Verify to unlock" chip when unverified), daily-prompt banner (GET /prompts/today; if alreadyPosted, show streak-neutral "You're in today ✓"), infinite scroll (IntersectionObserver + nextCursor, 10/batch, skeleton cards), pull-to-refresh on touch.
2. SnapCard: image (aspect-preserving, blurred-state images show a subtle 'auto-blurred for privacy' badge), author row (pseudonym chip with a mask icon when anonymous; company badge when present), caption, action row: like (optimistic toggle with reconciliation on error), comment count, suggestion count (💡, lime accent), overflow menu (Edit within window / Delete for viewerIsAuthor; Report otherwise -> reason sheet posting to /reports).
3. Composer (/snap/new, launched from a prominent FAB): camera/gallery input -> client-side downscale to max 1600px + JPEG re-encode (canvas) -> POST /media/uploads -> PUT bytes -> poll /media/:id/status with states: scanning spinner, 'blurred' shows the blurred preview with copy "We blurred this — looks like a screen. Screens often leak private info." and lets the user proceed or retake, 'rejected' blocks with retake. Pre-capture nudge line: "No computer screens — show us the vibe instead ☕". Caption field (280 chars, live counter), anonymous toggle (switch flips the author preview between the user's real avatar/name and a preview pseudonym with copy "Posting as BlueFox_7 — your identity is encrypted and unlinkable"), Publish -> POST /snaps -> navigate to feed with the new snap prepended.
4. Snap detail (/snap/:id): full card + tabbed Comments / Suggestions lists (paginated), input with kind selector (comment vs suggestion, suggestion styled lime with 💡), per-item edit/delete for authors, anonymous toggle on the input.
5. Profile (/u/:userId and /me): header (avatar, name, job title, industry, company badge), grid of public snaps; /me adds an 'Anonymous' filter chip revealing own anonymous snaps (marked with the mask icon).
Acceptance: RTL tests for optimistic like rollback, composer state machine (scanning->blurred->publish), 280-char enforcement, and anonymous-toggle preview; Lighthouse PWA + performance ≥ 90 on the feed route with 20 seeded snaps.
```

---

## Phase 11 — Hardening, tests & deploy readiness

```text
Context: feature-complete Breakroom monorepo (Phases 1–10).

1. Security pass (server): helmet CSP tuned for the SPA; strict CORS from env; request-size limits verified; add per-route rate limits exactly as the conventions table specifies (magic-link 5/hr/email, OTP request 3/hr, OTP confirm 5/verification, snaps 3/day + 1/prompt, interactions 30/hr, likes 200/hr, reports 20/day) with supertest proof for each; pino redaction list covers authorization header, body.workEmail, body.email, body.token, body.code; dependency audit clean.
2. Privacy audit script (server/scripts/privacy-audit.ts): connects to the DB and asserts invariants — no column named like '%work_email%' except work_email_hmac; every anonymous culture_snaps row (is_anonymous AND author_user_id IS NULL) has a vault row and vice versa; same for interactions; prints PASS/FAIL per invariant, exits non-zero on failure. Wire into CI.
3. Test completion: coverage target 80% lines on server modules auth/verification/media/snaps/feed; add one end-to-end happy-path script (scripts/e2e.ts) that exercises: signup -> verify company -> upload -> post anonymous snap -> second user comments a suggestion -> feed shows both -> report -> moderator blurs.
4. Ops: multi-stage Dockerfiles for server and web (nginx static for web with /api proxy), docker-compose.yml (postgres:15, minio, mailhog, server with MEDIA_WORKER=1 FEED_JOB=1, web), GitHub Actions workflow: lint -> migrate against service postgres -> test -> privacy-audit -> build images.
5. README: env var table, local quickstart, deploy notes (managed Postgres; VAULT_KEY/peppers in a secret manager, explicitly never in the DB or repo; S3+CDN; single-node deploy is fine — do not introduce load balancers, queues, or microservices).
Acceptance: docker compose up serves the full app at localhost; CI green; privacy-audit passes; e2e script completes.
```

---

## Execution order & dependency map

| Phase | Depends on | Ships |
|---|---|---|
| 1 | — | Monorepo, tooling, health check, API client |
| 2 | 1 | Full schema + seeds + counter-trigger tests |
| 3 | 2 | Crypto lib, error/rate-limit middleware, magic-link auth |
| 4 | 3 | OTP company verification (privacy-critical path) |
| 5 | 3 | Media presign + Compliance Shield scanner/worker |
| 6 | 4, 5 | Prompts, snap CRUD, likes, anonymity vault |
| 7 | 6 | Comments/suggestions, hybrid 60/25/15 feed, trending job |
| 8 | 7 | Reports + moderation console API |
| 9 | 3, 4 | Web shell, auth & verification UX |
| 10 | 6–9 | Composer, feed, engagement, profiles |
| 11 | all | Hardening, privacy audit, CI/CD, Docker |

Phases 4/5 and 9 can run in parallel with separate LLM sessions if desired; everything else is strictly sequential.

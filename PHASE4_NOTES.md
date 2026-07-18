# Phase 4 — Media Upload

## What Was Built

**Endpoint:** `POST /api/v1/snaps/upload` (authenticated)

An image upload pipeline using **multer** (memory storage) + **sharp** for server-side processing:

| Step | Detail |
|---|---|
| Auth | JWT via `Authorization: Bearer <token>` (reuses Phase 3 `protect` middleware) |
| Accept | `multipart/form-data`, field name `image` |
| Validate | jpeg / png / webp only, max 5 MB |
| Resize | Max 1200 px width, aspect ratio preserved, no upscaling |
| Convert | Output as `.webp`, quality ≈ 80 |
| Privacy | ALL metadata stripped (see below) |
| Save | `backend/uploads/<uuid>.webp` — UUID v4 filename |
| Serve | Static at `/uploads/<uuid>.webp` |

**Response:** `{ success: true, imageUrl: "/uploads/<uuid>.webp" }`

## Privacy Measures

1. **EXIF / GPS / ICC stripping** — sharp strips all metadata by default when `.withMetadata()` is not called. The controller explicitly omits it, with a `PRIVACY GATE` comment marking this as the Phase 4 requirement.
2. **UUID filenames** — the original filename is never used, stored, or exposed. Each upload gets a `crypto.randomUUID()` name.
3. **No raw data logging** — error handlers log only error messages, never file contents or user-supplied filenames.

## How to Test with curl

```bash
# 1. Get a JWT (use your existing Phase 3 register/verify flow)
TOKEN="your_jwt_here"

# 2. Upload an image
curl -X POST http://localhost:5000/api/v1/snaps/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "image=@path/to/photo.jpg"

# Expected: { "success": true, "imageUrl": "/uploads/<uuid>.webp" }

# 3. Verify the file is served
curl -I http://localhost:5000/uploads/<uuid>.webp
# Expected: 200 OK, Content-Type: image/webp

# 4. Test rejection — wrong file type
curl -X POST http://localhost:5000/api/v1/snaps/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "image=@readme.txt"
# Expected: 400 { "success": false, "error": "Only jpeg, png, and webp images are allowed" }

# 5. Test rejection — no auth
curl -X POST http://localhost:5000/api/v1/snaps/upload \
  -F "image=@photo.jpg"
# Expected: 401 { "success": false, "error": "No token provided" }
```

## Files Changed

| File | Change |
|---|---|
| `backend/src/config/upload.js` | **NEW** — multer config |
| `backend/src/controllers/snapController.js` | **NEW** — sharp processing + privacy gate |
| `backend/src/routes/snapRoutes.js` | **NEW** — route + multer error handler |
| `backend/src/server.js` | **MODIFIED** — static `/uploads` serving + snap route mount |
| `PHASE4_NOTES.md` | **NEW** — this file |

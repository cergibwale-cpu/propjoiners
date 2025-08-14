# PropJoiner — Real Estate Redirector with Analytics

High‑tech, fast, and deployable web app:
- CTA buttons redirect to a configurable client URL
- Mobile number OTP-based registration (Twilio optional; dev prints OTP to console)
- Analytics: visitors, registrations, CTA clicks, drop‑offs
- Admin dashboard with charts, CSV/PDF export
- Theme colors: Black, Yellow, Green, Orange

## Quick Start

```bash
cd propjoiner
cp .env.example .env
# Edit .env for ADMIN_* and CLIENT_REDIRECT_URL as needed

npm install
npm run start
```

App runs on http://localhost:8080

### Admin Login
The admin is seeded automatically using `.env` values:
- Email: `ADMIN_EMAIL`
- Password: `ADMIN_PASSWORD`

Visit http://localhost:8080/admin

### OTP
- If Twilio env vars are set, OTP SMS is sent.
- If not set, the OTP is printed to the server console for testing.

### Tracking
- Visits are recorded on GET `/` and `/page/*`
- CTA click tracking and redirect at `/api/redirect/:button`
- Registration attempts tracked; drop‑off = attempts minus completed verifications

### Exports
- CSV: `/api/admin/export/csv`
- PDF summary: `/api/admin/export/summary.pdf`

### Change Redirect URL
- Admin dashboard "Client Redirect URL" field
- Or via API `POST /api/admin/redirect-url` with JSON `{ "url": "https://..." }`

## Deploy Notes
- Behind a reverse proxy (Nginx) serving `/public`
- Ensure persistent storage for `propjoiner.db`
- Set proper `NODE_ENV=production`
- Use HTTPS, secure Twilio webhook ip allowlisting (if added later)

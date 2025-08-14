const API = {
  redirectUrl: '/api/redirect-url',
  redirect: (btn) => `/api/redirect/${encodeURIComponent(btn)}`,
  sendOtp: '/api/auth/send-otp',
  verifyOtp: '/api/auth/verify-otp',
  contact: '/api/contact'
};

const yearEl = document.getElementById('year');
if (yearEl) yearEl.textContent = new Date().getFullYear();

// CTA buttons: simply redirect, but attach a quick GET to record click on server (handled by server via redirect route)
document.querySelectorAll('[data-btn]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const which = btn.getAttribute('data-btn');
    window.location.href = API.redirect(which);
  });
});

// OTP flow
const step1 = document.getElementById('otp-step1');
const step2 = document.getElementById('otp-step2');
const otpMsg = document.getElementById('otpMsg');
let attemptId = null;

document.getElementById('sendOtp')?.addEventListener('click', async () => {
  const phone = document.getElementById('phone').value.trim();
  if (!phone) { otpMsg.textContent = 'Enter phone'; return; }
  const res = await fetch(API.sendOtp, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ phone })
  });
  const data = await res.json();
  if (data.ok) {
    attemptId = data.attemptId;
    step1.classList.add('hidden');
    step2.classList.remove('hidden');
    otpMsg.textContent = 'OTP sent. (In dev, check server console)';
  } else {
    otpMsg.textContent = data.error || 'Failed to send OTP';
  }
});

document.getElementById('verifyOtp')?.addEventListener('click', async () => {
  const code = document.getElementById('otp').value.trim();
  const phone = document.getElementById('phone').value.trim();
  const name = document.getElementById('name').value.trim();
  const email = document.getElementById('email').value.trim();
  if (!attemptId || !code || !phone) { otpMsg.textContent = 'Enter OTP'; return; }
  const res = await fetch(API.verifyOtp, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ attemptId, phone, code, name, email })
  });
  const data = await res.json();
  if (data.ok) {
    localStorage.setItem('propjoiner_user_id', data.userId);
    otpMsg.textContent = 'Verified! You can click any button above.';
  } else {
    otpMsg.textContent = data.error || 'Verification failed';
  }
});

// Contact form
document.getElementById('contactForm')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = Object.fromEntries(fd.entries());
  const res = await fetch(API.contact, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  document.getElementById('contactMsg').textContent = data.ok ? 'Sent!' : (data.error || 'Failed');
});

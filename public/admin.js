const API = {
  login: '/api/admin/login',
  stats: '/api/admin/stats',
  setUrl: '/api/admin/redirect-url',
  getUrl: '/api/redirect-url',
  exportCsv: '/api/admin/export/csv',
  exportPdf: '/api/admin/export/summary.pdf'
};
let token = '';

async function adminLogin() {
  const email = document.getElementById('adminEmail').value.trim();
  const password = document.getElementById('adminPass').value.trim();
  const res = await fetch(API.login, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (data.token) {
    token = data.token;
    document.getElementById('loginBox').classList.add('hidden');
    document.getElementById('dash').classList.remove('hidden');
    await loadStats();
    const urlRes = await fetch(API.getUrl);
    const urlData = await urlRes.json();
    document.getElementById('redirectUrl').value = urlData.url;
    document.getElementById('csvLink').href = API.exportCsv + '?t=' + Date.now();
    document.getElementById('pdfLink').href = API.exportPdf + '?t=' + Date.now();
  } else {
    document.getElementById('adminMsg').textContent = data.error || 'Login failed';
  }
}

document.getElementById('adminLoginBtn').addEventListener('click', adminLogin);

async function loadStats() {
  const res = await fetch(API.stats, { headers: { 'Authorization': 'Bearer ' + token }});
  const s = await res.json();
  document.getElementById('statVisitors').textContent = s.totalVisitors;
  document.getElementById('statUsers').textContent = s.totalUsers;
  document.getElementById('statClicks').textContent = s.totalClicks;
  document.getElementById('statDrop').textContent = s.dropOff;

  // Draw charts
  const days = (s.timeseries.visitsByDay || []).map(d => d.day);
  const visits = (s.timeseries.visitsByDay || []).map(d => d.c);
  const regs = (s.timeseries.regsByDay || []).map(d => d.c);
  const clicks = (s.timeseries.clicksByDay || []).map(d => d.c);

  new Chart(document.getElementById('visitsChart').getContext('2d'), {
    type:'line', data:{ labels: days, datasets:[{ label:'Visits', data: visits }]},
    options:{ responsive:true, maintainAspectRatio:false }
  });
  new Chart(document.getElementById('regsChart').getContext('2d'), {
    type:'line', data:{ labels: days, datasets:[{ label:'Registrations', data: regs }]},
    options:{ responsive:true, maintainAspectRatio:false }
  });
  new Chart(document.getElementById('clicksChart').getContext('2d'), {
    type:'line', data:{ labels: days, datasets:[{ label:'Clicks', data: clicks }]},
    options:{ responsive:true, maintainAspectRatio:false }
  });
}

document.getElementById('saveUrlBtn').addEventListener('click', async () => {
  const url = document.getElementById('redirectUrl').value.trim();
  const res = await fetch(API.setUrl, {
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},
    body: JSON.stringify({ url })
  });
  const data = await res.json();
  alert(data.ok ? 'Saved!' : (data.error || 'Failed'));
});

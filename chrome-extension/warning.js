document.addEventListener('DOMContentLoaded', async () => {
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = decodeURIComponent(urlParams.get('url'));
  
  // Fixed URL display
  const blockedUrlElement = document.getElementById('blockedUrl');
  if (blockedUrlElement) {
    blockedUrlElement.textContent = blockedUrl;
  }

  // Risk display logic
  try {
    const response = await chrome.runtime.sendMessage({
      action: 'getRiskData',
      url: blockedUrl
    });
    
    document.getElementById('riskFill').style.width = `${response.risk_score}%`;
    document.getElementById('riskScore').textContent = `${response.risk_score}% Risk`;
    
    document.getElementById('reasonsList').innerHTML = response.flags
      .map(flag => `<div class="flag-item">⚠️ ${flag}</div>`)
      .join('');
      
  } catch (error) {
    document.getElementById('reasonsList').innerHTML = 
      `<div class="flag-item">❌ ${error.message}</div>`;
  }
// Add after the existing code
document.getElementById('proceedBtn')?.addEventListener('click', () => {
  chrome.runtime.sendMessage({
    action: 'allowUrl',
    url: blockedUrl
  }, () => {
    window.location.href = blockedUrl;
  });
});

document.getElementById('backBtn')?.addEventListener('click', () => {
  chrome.tabs.update({ url: 'https://www.google.com' }); // Or your safe URL
});
});
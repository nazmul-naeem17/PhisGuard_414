chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'check_url') {
    fetch('http://localhost:5000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: request.url })
    })
    .then(res => res.json())
    .then(data => sendResponse(data))
    .catch(err => console.error(err));
    return true;  // keep the messaging channel open
  }
});

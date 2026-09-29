function unique(values){ return [...new Set(values.filter(Boolean))]; }
function visible(el){ if(!el) return false; const s=getComputedStyle(el), r=el.getBoundingClientRect(); return s.display!=='none' && s.visibility!=='hidden' && r.width>0 && r.height>0; }
function textOf(el){ return (el?.innerText || el?.textContent || '').trim(); }
function unwrapGmailUrl(href){
  try { const u=new URL(href); const q=u.searchParams.get('q') || u.searchParams.get('url'); if(q && /google\.com$/i.test(u.hostname)) return decodeURIComponent(q); } catch{}
  return href;
}
function scanGmail(){
  const bodies=[...document.querySelectorAll('div.a3s.aiL, div.a3s')].filter(visible);
  if(!bodies.length) return {ok:false,error:'Open an individual email in Gmail first.'};
  // Use the currently visible message body and read sender/details from that same message container.
  const bodyEl=bodies[bodies.length-1];
  const message=bodyEl.closest('.adn') || bodyEl.closest('[role="listitem"]') || bodyEl.parentElement;
  const subjectEl=[...document.querySelectorAll('h2.hP, [data-thread-perm-id] h2, [role="main"] h2')].filter(visible).pop();
  const subject=textOf(subjectEl);
  const senderEl=[...(message?.querySelectorAll('span[email], [email].gD')||[])].filter(visible)[0] || [...document.querySelectorAll('span[email], [email].gD')].filter(visible).pop();
  const senderEmail=senderEl?.getAttribute('email') || '';
  const senderName=textOf(senderEl);
  const sender=senderEmail ? `${senderName && senderName!==senderEmail ? senderName+' ' : ''}<${senderEmail}>` : senderName;
  const body=textOf(bodyEl);
  const links=unique([...bodyEl.querySelectorAll('a[href]')].map(a=>unwrapGmailUrl(a.href)).filter(h=>/^https?:/i.test(h)));
  const attachmentRoot=message || document;
  const attachmentNodes=[...attachmentRoot.querySelectorAll('[download_url], .aQH .aV3, .aZo')].filter(visible);
  const attachments=unique(attachmentNodes.map(el=>el.getAttribute('download_url')?.split(':').pop() || textOf(el)).filter(Boolean));
  let replyTo='';
  const detailText=textOf(message);
  const replyMatch=detailText.match(/reply-to:\s*([^\n]+)/i);
  if(replyMatch) replyTo=replyMatch[1].trim();
  return {ok:true,email:{subject,sender,replyTo,body:body.slice(0,16000),links:links.slice(0,30),attachments:attachments.slice(0,20)}};
}
chrome.runtime.onMessage.addListener((message,_sender,sendResponse)=>{ if(message?.type==='PHISHY_SCAN_PAGE') sendResponse(scanGmail()); });

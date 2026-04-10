// content.js — FraudShield v4.3
(function(){
  const url=window.location.href;
  if(!url.startsWith("http://")&&!url.startsWith("https://")) return;
  setTimeout(()=>{
    chrome.runtime.sendMessage({type:"PROACTIVE_SCAN",url}).catch(()=>{});
  },1500);
})();
/**
 * email.js - newsletter subscription via EmailJS
 * EmailJS lets you send emails directly from JavaScript
 * no backend server required.
 * 1. Create a FREE account at https://www.emailjs.com
 * 2. Add an email service:
 *    Dashboard → Email Services → Add New Service
 *    → Connect your Gmail / Outlook / Yahoo etc.
 *    → Give it a name like cipher_service
 *    → Click Create Service
 *    → Copy the SERVICE_ID (e.g. "service_abc123")
 * 3. Create template 1 (notifices you of new subscribers)
 *    → Left sidebar → Email Templates → Create New Template
 *  Fill it like this:
 *  To email: (just write your own email)
 *  From name: CIPHER Newsletter
 *  Subject: New subscriber: {{from_name}}
 *  Press the button Edit Content and write this:
 *    New subscriber on CIPHER!
 *    Name:  {{from_name}}
 *    Email: {{from_email}}
 *  Click Save → Copy the Template ID — looks like template_xyz9876
 * 4. Create an email template 2 (welcome email to the subscriber):
 *    Email Templates → Create New Template again
 *    To email: {{from_email}}
 *    From name: CIPHER Team
 *    Subject: Welcome to CIPHER, {{from_name}}!
 *    Press the button Edit Content and write this:
 *      Hi {{from_name}},
 *      You're now subscribed to the CIPHER Weekly Intel Brief.
 *      Every Monday you'll get the top CVEs, threat research, and defensive tools - straight to your inbox.
 *      Stay sharp.
 *      - The CIPHER Team
 *    Click Save → Copy this Template ID too
 *  5. Get your Public Key
 *     Top right → click your account name → Account
 *     Under General tab → find Public Key
 *     Copy it - looks like AbCdEfGhIjKlMnOp
 *  6. Paste all the information into the file
 *     Open js/email.js and replace these 4 lines:
 *        const EMAILJS_PUBLIC_KEY       = 'YOUR_PUBLIC_KEY';
 *        const EMAILJS_SERVICE_ID       = 'YOUR_SERVICE_ID';
 *        const EMAILJS_NOTIFY_TEMPLATE  = 'YOUR_NOTIFY_TEMPLATE_ID';
 *        const EMAILJS_WELCOME_TEMPLATE = 'YOUR_WELCOME_TEMPLATE_ID';
 *      With your actual values, for example:
 *      const EMAILJS_PUBLIC_KEY       = 'AbCdEfGhIjKlMnOp';
 *      const EMAILJS_SERVICE_ID       = 'service_abc1234';
 *      const EMAILJS_NOTIFY_TEMPLATE  = 'template_xyz9876';
 *      const EMAILJS_WELCOME_TEMPLATE = 'template_def5432';
 * THAT'S IT. No server. No paid plan. */

(function () {
  'use strict';
  // FILL THESE IN
  const EMAILJS_PUBLIC_KEY      = '8Ph5eqK8ou9dkYkmC';        // from account → General
  const EMAILJS_SERVICE_ID      = 'service_m9qlkle';        // From Email Services
  const EMAILJS_NOTIFY_TEMPLATE = 'template_4zkae1e'; // Notifies YOU of new subscriber
  const EMAILJS_WELCOME_TEMPLATE= 'template_m9rhe5u'; // Sends welcome email to subscriber
  const CONFIGURED = EMAILJS_PUBLIC_KEY !== 'YOUR_PUBLIC_KEY';
  if (CONFIGURED && typeof emailjs !== 'undefined') {
    emailjs.init({ publicKey: EMAILJS_PUBLIC_KEY });
  }
  const form     = document.getElementById('newsletterForm');
  const nameEl   = document.getElementById('nameInput');
  const emailEl  = document.getElementById('emailInput');
  const msgEl    = document.getElementById('formMessage');
  const submitBtn= form?.querySelector('.btn-subscribe');
  if (!form) return;
  function setMsg(text, cls) {
    if (!msgEl) return;
    msgEl.textContent = text;
    msgEl.className   = 'newsletter-note ' + (cls || '');
  }
  function setLoading(loading) {
    if (!submitBtn) return;
    submitBtn.disabled    = loading;
    submitBtn.textContent = loading ? 'Sending...' : 'Subscribe →';
  }
  function validateEmail(e) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim());
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name  = (nameEl?.value  || 'Subscriber').trim();
    const email = (emailEl?.value || '').trim();
    emailEl?.classList.remove('error');
    if (!validateEmail(email)) {
      emailEl?.classList.add('error');
      setMsg('// Invalid email address - please try again.', 'error');
      return;
    }
    if (!CONFIGURED || typeof emailjs === 'undefined') {
      setMsg('// Demo mode: fill in EmailJS keys in js/email.js to enable real sending.', 'warn');
      window.CIPHER_UI?.toast('EmailJS not configured - see js/email.js', 'error');
      return;
    }
    setLoading(true);
    setMsg('// Connecting...', '');
    try {
      const params = {
        from_name:  name  || 'Subscriber',
        from_email: email,
        reply_to:   email,
      };
      // 1. Notify yourself of the new subscriber
      await emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_NOTIFY_TEMPLATE, params);
      // 2. Send welcome email to the subscriber
      await emailjs.send(EMAILJS_SERVICE_ID, EMAILJS_WELCOME_TEMPLATE, params);
      // Success
      if (emailEl) emailEl.value = '';
      if (nameEl)  nameEl.value  = '';
      setMsg(`// Welcome aboard, ${name || 'Operator'}! Check your inbox.`, 'success');
      window.CIPHER_UI?.toast('Subscribed! Check your inbox.', 'success');
    } catch (err) {
      console.error('EmailJS error:', err);
      setMsg('// Send failed - check your EmailJS config or try again.', 'error');
      window.CIPHER_UI?.toast('Subscription failed. Try again.', 'error');
    } finally {
      setLoading(false);
      // Reset message after 6 seconds
      setTimeout(() => setMsg('// NO TRACKING · UNSUBSCRIBE ANYTIME', ''), 6000);
    }
  });
  // Clear error state on input
  emailEl?.addEventListener('input', () => {
    emailEl.classList.remove('error');
    setMsg('// NO TRACKING · UNSUBSCRIBE ANYTIME', '');
  });
})();
